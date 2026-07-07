# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Complete repository refactoring into a flattened enterprise structure.
- Comprehensive technical documentation (`ARCHITECTURE.md`, `HOW_TO_RUN.md`).
- Multi-stage Docker setup.
- Initial API Gateway and Routing structure for FastAPI.
- Ollama LLM integration for AI-driven security analysis.
- Frida integration script hooks for dynamic analysis.

### Changed
- Moved frontend from `sudarshan/app` to `./frontend`.
- Moved backend from `sudarshan/backend` to `./backend`.
- Updated `docker-compose.yml` to reflect the new paths.

### Removed
- `MASTER_PLAN.md` and redundant `sudarshan/` root wrapper.
