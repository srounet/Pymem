import setuptools


setuptools.setup(
    name='Pymem',
    version='0.3',
    description='pymem: python memory access made easy',
    author='Fabien Reboia',
    author_email='srounet@gmail.com',
    maintainer='Fabien Reboia',
    maintainer_email='srounet@gmail.com',
    url='http://pymem.readthedocs.org/en/latest/',
    long_description="A python library for windows, providing the needed functions to start working on your own with memory editing",
    license="postcard license",
    packages = setuptools.find_packages(),
    platforms=["windows"],
    keywords='memory win32 windows process',
    classifiers=[
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Assembly',
        'Environment :: Win32 (MS Windows)',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
    ],
    install_requires=[
        'sphinx_rtd_theme'
    ],
)