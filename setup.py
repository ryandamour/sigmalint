# -*- coding: utf-8 -*-

# DO NOT EDIT THIS FILE!
# This file has been autogenerated by dephell <3
# https://github.com/dephell/dephell

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

readme = ''

setup(
    long_description=readme,
    name='sigmalint',
    version='0.2.0',
    description='A simple linter for Sigma rules',
    python_requires='==3.*,>=3.8.0',
    author='Ryan Plas',
    author_email='ryan.plas@stage2sec.com',
    entry_points={"console_scripts": ["sigmalint = sigmalint.sigmalint:cli"]},
    packages=['sigmalint', 'sigmalint.schema'],
    package_dir={"": "."},
    package_data={},
    install_requires=[
        'click==7.*,>=7.1.2', 'jsonschema==3.*,>=3.2.0', 'pyrx==0.*,>=0.3.0',
        'pyyaml==5.*,>=5.3.1'
    ],
    extras_require={
        "dev": ["pytest==5.*,>=5.4.3", "pytest-cov==2.*,>=2.10.0"]},
)
