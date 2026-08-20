"""Sets parameters and controls for package setup and installation."""

from setuptools import setup, find_packages


# Open and read our README markdown for the long description value
def readme():
    """Opens and reads the package's README."""
    with open("README.md", encoding="utf-8") as readme_file:
        return readme_file.read()


# Open, read and parse our requirements text to an array for the install_requires value
def requirements():
    """Opens and reads the package requirements.txt file."""
    with open("requirements.txt", encoding="utf-8") as requirements_file:
        return list(filter(None, requirements_file.read().split("\n")))


# Set our setup parameters
setup(
    name="scan_tech_assistant",
    author="Landon Bell",
    author_email="it_engineering@securitymetrics.com",
    description="A Chainlit chat app that helps scan technicians validate disputed Nessus findings.",
    long_description=readme(),
    long_description_content_type="text/markdown",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements(),
    python_requires=">=3.12",
)
