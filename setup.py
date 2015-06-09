import setuptools

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

#install_reqs = parse_requirements('requirements.txt')
#requirements = [str(ir.req) for ir in install_reqs]

setuptools.setup(
    name='Pymem',
    version='0.2a',
    description='pymem: python memory access made easy',
    author='Fabien Reboia',
    author_email='srounet@gmail.com',
    maintainer='Fabien Reboia',
    maintainer_email='srounet@gmail.com',
    url='http://pymem.readthedocs.org/en/latest/',
    download_url = 'https://github.com/srounet/pymem/tarball/0.2a',
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
    install_requires=requirements,
)