#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script to emulate/unpack IcedID stage 1/2 DLLs, and extract network domain if available.
Command line example:
$ python3 extract_iceid_domains.py -f ./sample.dll -o ./unpacked_data -r /qiling/examples

     Copyright 2021 VMware, Inc.
     License: GPLv2

This program is free software; you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.
"""
import argparse
import ctypes
import datetime
import glob
import hashlib
import logging
import os
import pefile
import qiling
import qiling.const


# Initialize logging
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

# Maximum timeout in microseconds (default 5min)
EMULATOR_TIMEOUT_MICROSECONDS = 60 * 5 * 1000 * 1000


class IcedIDConfig(ctypes.Structure):
    """Structure representing a C structure."""
    _fields_ = (
        ('id', ctypes.c_uint32),
        ('domain', ctypes.c_char*28)
    )


class IcedIDEmulator:
    """Emulate execution of IceID samples."""

    EXPORT_ENTRYPOINT = frozenset([b'PluginInit', b'update'])

    @staticmethod
    def decrypt_section_data(section: pefile.SectionStructure) -> IcedIDConfig:
        """Decrypt the section."""
        data = section.get_data(length=0x60)
        xor_0 = data[:0x20]
        xor_1 = data[0x40:0x40+0x20]
        decrypted_config = bytearray([a ^ b for a, b in zip(xor_0, xor_1)])
        return IcedIDConfig.from_buffer(decrypted_config)

    @staticmethod
    def is_stage1(parsed_pe: pefile.PE) -> bool:
        """Return whether the PE is likely to be a stage1 IcedID DLL."""
        try:
            return b'WINHTTP.dll' in set([entry.dll for entry in parsed_pe.DIRECTORY_ENTRY_IMPORT])
        except AttributeError:
            return False

    @staticmethod
    def extract_icedid_stage1_config(parsed_pe: pefile.PE) -> IcedIDConfig or None:
        """Extract the stage1 configuration or return None."""
        if IcedIDEmulator.is_stage1(parsed_pe):
            for section in parsed_pe.sections:
                if section.Name.rstrip(b'\x00') == b'.data':
                    return IcedIDEmulator.decrypt_section_data(section)
        return None

    @staticmethod
    def file_sha1(filepath: str) -> str:
        with open(filepath, "rb") as f:
            bytes = f.read()  # read entire file as bytes
            return hashlib.sha1(bytes).hexdigest()

    @staticmethod
    def get_generic_info(file_path: str) -> dict:
        """Return a dictionary of information related to the provided sample."""
        parsed_pe = pefile.PE(file_path)
        timestamp = datetime.datetime.utcfromtimestamp(parsed_pe.FILE_HEADER.TimeDateStamp)
        data = {
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "config_id": "",
            "config_domain": ""
        }
        config = IcedIDEmulator.extract_icedid_stage1_config(parsed_pe)
        if config:
            data["config_id"] = hex(config.id)
            data["config_domain"] = config.domain
        return data

    def __init__(
        self,
        file_path,
        rootfs_path,
        output_dir,
        entry_point=None,
        disable_log=False,
        disable_cache=False,
        timeout=None,
    ):
        """Constructor."""
        self.logger = logging.getLogger(__name__)
        self.file_path = file_path
        self.output_dir = output_dir
        self.disable_cache = disable_cache
        self.file_hash = self.file_sha1(file_path)
        self.memory_regions = []
        self.rootfs_path = rootfs_path
        # initialize emulator (x86_64 windows)
        self.ql = qiling.Qiling([file_path], os.path.join(rootfs_path, "rootfs/x8664_windows"))
        # hook VirtualAlloc() on exit
        self.ql.set_api("VirtualAlloc", self.hook_virtual_alloc, qiling.const.QL_INTERCEPT.EXIT)
        # hook VirtualAlloc() on enter
        self.ql.set_api("CreateThread", self.hook_create_thread, qiling.const.QL_INTERCEPT.ENTER)
        # hook Sleep() on exit
        self.ql.set_api("Sleep", self.hook_sleep, qiling.const.QL_INTERCEPT.EXIT)
        # disable logging
        if disable_log:
            self.ql.filter = []
        self.timeout = timeout or EMULATOR_TIMEOUT_MICROSECONDS
        self.entry_point = entry_point or self.find_entry_point()
        self.dump_paths = []
        self.domains = []

    def find_entry_point(self):
        """Heuristic to find entry points."""
        entrypoint_candidate = None
        self.logger.debug("Entry points found: %s", self.ql.loader.export_symbols)
        for addr, export in self.ql.loader.export_symbols.items():
            if export["name"] in self.EXPORT_ENTRYPOINT:
                self.logger.info("Found entrypoint {} at 0x{:08x} using heuristics".format(export["name"], addr))
                entrypoint_candidate = addr

        if entrypoint_candidate is None:
            raise RuntimeError("No entry point found")
        return entrypoint_candidate

    def dump_memory_region(self, ql, address, size):
        """Dump the memory region to disk."""
        try:
            self.logger.info("Dump memory region at address: %s - size: %s", hex(address), hex(size))
            memory_dump = ql.mem.read(address, size)
            dump_path = os.path.join(self.output_dir, "{}_unpacked_{:08x}.bin".format(self.file_hash, address))
            with open(dump_path, "wb") as f:
                f.write(memory_dump)
                self.dump_paths.append(dump_path)
                self.logger.info("Wrote dump to path {}".format(dump_path))
        except Exception as err:
            self.logger.info("Unable to read memory region at address: %s. Error: %s", hex(address), str(err))

    @classmethod
    def is_pe(cls, ql, address):
        """Return whether 'address' is pointing to likely PE data."""
        return ql.mem.read(address, 2) == b"MZ"

    def dump_memory(self, ql):
        """Dump all found memory regions to file."""
        ql.mem.show_mapinfo()
        for pe_address, pe_size in self.find_pe_regions(ql):
            self.logger.info("Found PE in 0x{:08x} of size 0x{:08x}".format(pe_address, pe_size))
            self.dump_memory_region(ql, pe_address, pe_size)

    def find_pe_regions(self, ql):
        """Return an iterator over all memory regions containing a PE file."""
        for region_address, region_size in self.memory_regions:
            if self.is_pe(ql, region_address):
                yield region_address, region_size

    def hook_virtual_alloc(self, ql, addr, params, ret_val):
        """Hook the 'VirtualAlloc' API."""
        _ = ql, addr
        self.logger.info("VirtualAlloc of size 0x{:08x}".format(params["dwSize"]))
        self.memory_regions.append((ret_val, params["dwSize"]))

    def hook_create_thread(self, ql, addr, params):
        """Hook the 'CreateThread' API."""
        _ = addr, params
        self.logger.info("CreateThread - Stopping execution, looking for allocated PE")
        self.dump_memory(ql)
        raise RuntimeError("Stop emulation")

    def hook_sleep(self, ql, addr, params, ret_val):
        """Hook 'Sleep' API."""
        _ = addr, params, ret_val
        self.logger.info("Sleep - Stopping execution, looking for allocated PE")
        self.dump_memory(ql)
        raise RuntimeError("Stop emulation")

    def emulate_file(self):
        """Emulate a file."""
        glob_path = os.path.join(self.output_dir, "{}_unpacked_*.bin".format(self.file_hash))
        dump_paths = glob.glob(glob_path)
        if dump_paths and not self.disable_cache:
            self.logger.info("File '{}' has {} cached dumps".format(self.file_hash, len(dump_paths)))
            self.dump_paths = dump_paths
        else:
            try:
                self.ql.run(begin=self.entry_point, timeout=self.timeout or 0)
            except Exception as err:
                self.logger.error("Emulating %s crashed: %s", self.file_hash, str(err))
                self.dump_memory(self.ql)

    def parse_extracted_data(self):
        """Process the results."""
        data = []
        pe_data = IcedIDEmulator.get_generic_info(self.file_path)
        data.append(pe_data)
        for dump_path in self.dump_paths:
            pe_data = IcedIDEmulator.get_generic_info(dump_path)
            pe_data["source"] = self.file_hash
            data.append(pe_data)
        qiling_domains = [x["config_domain"].decode("utf-8", errors="ignore") for x in data if x["config_domain"]]
        if qiling_domains:
            self.logger.info("File '%s' has indicators: %s", self.file_hash, ",".join(qiling_domains))
            self.domains = qiling_domains
        else:
            self.logger.info("File '%s' did NOT lead to network indicators", self.file_hash)


def main():
    """Unpack sample."""
    parser = argparse.ArgumentParser(description="Unpacks a IcedID stage 1 or 2 DLL and extract Network Domain")
    parser.add_argument(
        "-f",
        "--sample-path",
        dest="sample_path",
        default=None,
        required=True,
        help="input sample",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default=None,
        required=True,
        help="output directory",
    )
    parser.add_argument(
        "-r",
        "--rootfs-path",
        dest="rootfs_path",
        default="./data",
        help="path containing the rootfs directory for Qiling. 'rootfs/x8664_windows' will be appended to this path.",
    )
    parser.add_argument(
        "-a",
        "--disable_cache",
        dest="disable_cache",
        action="store_true",
        default=False,
        help="whether the cache should be ignored",
    )

    # Parse options and config
    args = parser.parse_args()

    sample_path = args.sample_path
    output_dir = args.output_dir
    disable_cache = args.disable_cache
    rootfs_path = args.rootfs_path

    emu = IcedIDEmulator(sample_path, rootfs_path, output_dir, disable_cache=disable_cache)
    emu.emulate_file()
    emu.parse_extracted_data()

    return 0


if __name__ == "__main__":
    main()
