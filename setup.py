import re
from setuptools import setup


def load_dependencies(filename):
    install_requires = []
    dependency_links = []
    for line in open(filename):
        line = line.decode('utf-8').strip()
        m = re.match(r'http.+#egg=(?P<pkgname>.+)', line)
        if m:
            dependency_links.append(line)
            install_requires.append(m.groupdict()['pkgname'])
        else:
            install_requires.append(line)
    return install_requires, dependency_links

install_requires, dependency_links = load_dependencies('requirements.txt')


setup(
    name='Pymem',
    version='0.1',
    description='pymem: python memory access made easy',
    author='Fabien Reboia',
    author_email='srounet@gmail.com',
    maintainer='Fabien Reboia',
    maintainer_email='srounet@gmail.com',
    url=' http://www.pymem.org/',
    long_description="A python library for windows, providing the needed functions to start working on your own with memory editing",
    license="postcard license",
    packages=['pymem'],
    platforms=["windows"],
    keywords='memory win32 windows process',
    classifiers=[
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Assembly',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
    ],
    install_requires=install_requires,
    dependency_links=dependency_links,
)