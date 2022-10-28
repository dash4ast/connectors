#!/usr/bin/env python

from setuptools import setup

setup(
    name='connectors',
    version='6.0.9',
    package_dir={'': 'src'},
    packages=['connectors',
              'connectors.db',
              'connectors.endpoints',
              'connectors.persistence'],
    author='dash4ast',
    url='www.dash4ast.com',
    python_requires='>=3.4, <4',
    install_requires=[
        'blackduck==1.0.4',
        'python-sonarqube-api',
        'sqlalchemy==1.3.*',
        'PyMySQL==0.10.*',
        'flask==2.0.*',
        'requests==2.25.*',
        'flasgger==0.9.*',
        'flask-cors==3.0.*',
        'flask-deprecate',
        'waitress',
        'marshmallow==3.12.*',
        'psycopg2'
    ]
)
