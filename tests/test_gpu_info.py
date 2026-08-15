"""Tests for hashcat GPU info parsing and alerts."""

from __future__ import annotations

from modules.cracking import (
    GpuInfo,
    format_gpu_info_block,
    hashcat_output_indicates_gpu_error,
    parse_hashcat_backend,
)

HASHCAT_I_OK = """
hashcat (v7.1.2) starting in backend information mode

CUDA Info:
==========

CUDA.Version.: 12.2

Backend Device ID #1
  Type...........: GPU
  Vendor.ID......: 32
  Vendor.........: NVIDIA Corporation
  Name...........: NVIDIA GeForce RTX 2050
  Version........: OpenCL 3.0 CUDA
  Processor(s)...: 16
  Clock..........: 1470
  Memory.Total...: 4096 MB
  Module.Backend.: CUDA
"""

HASHCAT_I_FAIL = """
hashcat (v7.1.2) starting in backend information mode

clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR

ATTENTION! No OpenCL, HIP or CUDA compatible platform found.

You are probably missing the OpenCL, CUDA or HIP runtime installation.
"""


def test_parse_hashcat_backend_ok():
    ok, devices, summary = parse_hashcat_backend(HASHCAT_I_OK)
    assert ok is True
    assert len(devices) == 1
    assert "RTX 2050" in devices[0]["name"]
    assert devices[0]["type"].upper() == "GPU"
    assert "4096" in devices[0]["memory"]
    assert "ready" in summary.lower()


def test_parse_hashcat_backend_missing_runtime():
    ok, devices, summary = parse_hashcat_backend(HASHCAT_I_FAIL)
    assert ok is False
    assert devices == []
    assert "opencl" in summary.lower() or "cuda" in summary.lower()


def test_hashcat_output_indicates_gpu_error():
    assert hashcat_output_indicates_gpu_error(HASHCAT_I_FAIL) is True
    assert hashcat_output_indicates_gpu_error("Status.........: Exhausted") is False


def test_format_gpu_info_block_includes_pci_and_backend():
    info = GpuInfo(
        pci_devices=["01:00.0 VGA compatible controller: NVIDIA GeForce RTX 2050"],
        backend_ok=False,
        backend_error="No OpenCL / HIP / CUDA compatible platform found.",
        backend_summary="No OpenCL / HIP / CUDA compatible platform found.",
    )
    text = format_gpu_info_block(info)
    assert "RTX 2050" in text
    assert "Graphics card" in text
    assert "hashcat backends" in text
