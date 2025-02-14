from setuptools import setup, find_packages

setup(
    name="mirror-flowers",
    version="1.0.0",
    description="AI-driven Code Security Audit Tool",
    author="Ky0toFu",
    author_email="",  # 如果有的话
    url="https://github.com/Ky0toFu/Mirror-Flowers",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "python-multipart",
        "aiofiles",
        "httpx",
        "openai",
        "chromadb",
        "sentence-transformers",
        "pydantic",
        "pydantic-settings",
        "python-dotenv",
        "langchain",
        "langchain-community",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-asyncio",
            "black",
            "isort",
            "flake8",
            "mypy",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
) 