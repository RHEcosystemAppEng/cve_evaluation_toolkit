# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of CVE Evaluation Toolkit
- API client for fetching CVE analysis jobs and traces
- Data extractor for parsing nested API responses
- LLM-based evaluation metrics using DeepEval framework:
  - Checklist generation quality (prompt alignment, quality)
  - Investigation step quality (4 metrics: answer quality, reasoning quality, tool selection quality, tool call integrity)
  - Summary quality
  - Justification quality
  - Intel score fidelity
- Kubernetes/OpenShift deployment configurations with Kustomize
- Support for NVIDIA NIM API as LLM judge
- Compatibility layer for both standalone and integrated deployment
- Comprehensive documentation and deployment guides

### Changed
- Migrated from Fireworks API to NVIDIA NIM for LLM judge
- Separated evaluation logic from main vulnerability-analysis project
- Refactored investigation metrics to split tool selection into semantic and syntactic evaluation
- Updated API payload format to match ML-OPS endpoint schema

### Technical Details
- Python 3.12+
- Uses uv for dependency management
- Multi-stage Docker build for optimized images
- Separate dev and prod Kustomize overlays
- Configurable via environment variables

## [0.1.0] - 2026-02-19

### Added
- Initial project structure
- Core evaluation pipeline implementation
- Docker and Kustomize deployment configurations
- Documentation and setup guides
