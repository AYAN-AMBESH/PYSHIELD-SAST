from setuptools import setup, find_packages

setup(
    name="pyshield-sast",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "pyshield = pyshield.cli:main"
        ]
    },
    author="Gaurav Gogia",
    description="A Python Static Application Security Testing (SAST) tool for finding vulnerabilities via AST.",
    python_requires=">=3.7",
)
