from setuptools import find_packages
from setuptools import setup

setup(
    name='pre-commit-hooks',
    description='Pre-commit hooks for validating HTML',
    url='https://github.com/pirogoeth/pre-commit-hooks-html',
    version='1.3.11',

    author='Lucas Cimon',
    author_email='lucas.cimon@gmail.com',

    platforms='linux',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],

    packages=find_packages('.'),
    install_requires=[
        'html5validator',
        'jinja2',
        'pybars3',
        'six',
    ],
    entry_points={
        'console_scripts': [
            'validate_html = pre_commit_hooks.validate_html:main',
        ],
    },
)
