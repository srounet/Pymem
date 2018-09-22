import setuptools


setuptools.setup(
    name='Pymem',
    version='0.4',
    description='pymem: python memory access made easy',
    author='Fabien Reboia',
    author_email='srounet@gmail.com',
    maintainer='Fabien Reboia',
    maintainer_email='srounet@gmail.com',
    url='http://pymem.readthedocs.org/en/latest/',
    long_description="A python library for windows, providing the needed functions to start working on your own with memory editing",
    license="mit",
    packages=setuptools.find_packages(),
    platforms=["windows"],
    keywords='memory win32 windows process',
    classifiers=[
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
    ],
    install_requires=[
        'sphinx_rtd_theme'
    ],
)
