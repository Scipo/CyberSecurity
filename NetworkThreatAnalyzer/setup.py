from setuptools import  setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="network-threat-analyzer",
    version="1.0.0",
    author="Network Security Developer",
    description="A cross-platform network threat intelligence analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: Beta",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "network-threat-analyzer=main:main",
        ],
    },
    include_package_data=True,
)