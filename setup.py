import os
import pathlib
import setuptools

ROOT = str(pathlib.Path(__file__).parent)

extras = {
    'speed': ['regex']
}

if os.path.isfile(ROOT + '/requirements-doc.txt'):
    with open(ROOT + '/requirements-doc.txt', encoding='utf-8', mode='r+') as fp:
        extras['doc'] = fp.read().splitlines()

if os.path.isfile(ROOT + '/requirements-test.txt'):
    with open(ROOT + '/requirements-test.txt', encoding='utf-8', mode='r+') as fp:
        extras['test'] = fp.read().splitlines()

long_description = ''
if os.path.isfile(ROOT + '/PYPI-README.md'):
    with open(ROOT + '/PYPI-README.md', encoding="utf-8", mode='r+') as fp:
        long_description = fp.read()


setuptools.setup(
    name='Pymem',
    version='1.13.1',
    long_description=long_description,
    long_description_content_type="text/markdown",
    description='pymem: python memory access made easy',
    author='Fabien Reboia',
    author_email='srounet@gmail.com',
    maintainer='Fabien Reboia',
    maintainer_email='srounet@gmail.com',
    url='http://pymem.readthedocs.org/en/latest/',
    license="mit",
    packages=["pymem", "pymem.ressources"],
    platforms=["windows"],
    keywords='memory win32 windows process',
    classifiers=[
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
    ],
    extras_require=extras,
)
