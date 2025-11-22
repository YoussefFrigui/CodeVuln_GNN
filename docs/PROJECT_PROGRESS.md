# Project Progress Report: GNN-Based Vulnerability Detection in Python Code

## Introduction

This project develops a Graph Neural Network (GNN) model for detecting security vulnerabilities in Python source code. By leveraging real-world vulnerability data from GitHub Security Advisories and safe code examples from CodeSearchNet, we aim to create a robust, labeled dataset for training machine learning models to identify potential security flaws in code.

## Objectives

- **Primary Goal**: Build an effective GNN model for vulnerability detection in Python code.
- **Data Collection**: Acquire and process real-world vulnerability data from security advisories.
- **Dataset Creation**: Generate a balanced, labeled dataset combining vulnerable and safe code examples.
- **Model Development**: Implement and train a GNN architecture for code analysis.
- **Evaluation**: Assess model performance using standard metrics and compare against baselines.

## Methodology

### Data Pipeline

1. **Advisory Acquisition**: Clone and parse GitHub Security Advisory Database.
2. **Filtering**: Extract Python-related vulnerabilities (PyPI ecosystem).
3. **Commit Extraction**: Identify fix commit URLs from advisories.
4. **Diff Analysis**: Fetch commit data and parse diffs via GitHub API.
5. **Snippet Extraction**: Extract vulnerable and patched code snippets.
6. **Dataset Integration**: Combine with safe examples from CodeSearchNet.

### Technical Approach

- **Vulnerability Source**: Real security advisories with confirmed CWE classifications.
- **Safe Examples**: Function-level Python code from CodeSearchNet dataset.
- **Labeling**: Binary classification (vulnerable/safe) with metadata.
- **GNN Implementation**: Use graph representations of code (AST/Control Flow Graphs).

## Progress and Results

### Completed Phases

#### Phase 1: Data Acquisition 

- Successfully cloned GitHub Security Advisory Database (24,192 advisories).
- Integrated existing CodeSearchNet Python dataset (457,461 functions).

#### Phase 2: Advisory Processing 

- Filtered 3,928 Python-related security advisories from the database.
- Extracted 2,813 advisories containing fix commit URLs.

#### Phase 3: Commit Data Retrieval 

- Implemented robust GitHub API client with retry logic and rate limiting.
- Fetched commit details and diffs for all identified advisories.

#### Phase 4: Code Extraction

- Developed diff parsing algorithms to extract vulnerable/patched code snippets.
- Generated 5,551 labeled vulnerable code pairs from real security fixes.

#### Phase 5: Dataset Creation 

- Combined vulnerable examples with 10,000 safe CodeSearchNet functions.
- Created a dataset of 15,551 labeled examples in JSON format.

### Progess Highlights

- **Data Quality**: Real-world vulnerabilities with CWE classifications and metadata.
- **Scalability**: Scripts handle large datasets with progress tracking and error recovery.

### Dataset Summary

- **Vulnerable Examples**: Sourced from 2,813 unique security advisories.
- **Safe Examples**: Diverse Python functions from open-source repositories.
- **Format**: Structured JSON with code snippets, labels, and metadata.

## Challenges and Solutions

### Technical Challenges

- **API Rate Limiting**: GitHub API restrictions on request frequency.
  - **Solution**: Implemented exponential backoff, token authentication, and batch processing.
- **Diff Parsing Complexity**: Extracting meaningful code snippets from Git diffs.
  - **Solution**: Developed custom parsing logic for unified diff format.
- **Data Volume**: Processing thousands of advisories and API responses.
  - **Solution**: Incremental saving, progress tracking, and modular script design.

### Data Quality Issues

- **Incomplete Advisories**: Some advisories lack commit references.
  - **Solution**: Robust filtering and fallback mechanisms.
- **Code Context**: Diffs show changes but not full function context.
  - **Solution**: Experimental full-function extraction script for future enhancement.

## Current Status

- **Data Pipeline**: Fully operational and tested.
- **Dataset**: Ready for model training and validation.
- **Scripts**: Well-documented and modular for easy maintenance.
- **Documentation**: Comprehensive README and progress tracking.

The project has successfully transitioned from data collection to dataset creation, establishing a solid foundation for the machine learning phase.

## Future Work



- **Data Enhancement**: Implement full-function extraction for better context.
- **Preprocessing**: Tokenize code and build graph representations for GNN input.
- **Model Architecture**: Design and implement GNN layers using PyTorch Geometric.


- **Training**: Train GNN model on labeled dataset with appropriate loss functions.
- **Evaluation**: Benchmark against CodeSearchNet test set and baseline models.
- **Hyperparameter Tuning**: Optimize model performance through systematic experimentation.

- **Model Refinement**: Incorporate advanced features (attention mechanisms, multi-modal inputs).
- **Generalization**: Extend to other programming languages.
- **Deployment**: Develop inference pipeline for real-world code analysis.
- **Publication**: Prepare results for academic conferences/journals.

## Conclusion

This project has made significant progress in establishing a comprehensive pipeline for vulnerability detection dataset creation. The successful extraction and labeling of 15,551 code examples from real security advisories represents a valuable contribution to the field of AI-driven code security analysis.

The automated, reproducible pipeline ensures scalability and provides a foundation for developing state-of-the-art GNN models for vulnerability detection. Future work will focus on model development and rigorous evaluation to validate the approach's effectiveness.

---