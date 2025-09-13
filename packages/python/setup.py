from setuptools import setup, find_packages

setup(
    name="maat-cross-lang-crypto",
    version="1.0.0",
    description="Cross-language encryption package",
    packages=find_packages(),
    install_requires=["cryptography>=3.0.0"]
)