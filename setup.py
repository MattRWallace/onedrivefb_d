#!/usr/bin/python3

import os
from setuptools import setup, find_packages

try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'README.md')) as f:
        readme = f.read()
except IOError:
    readme = 'Please read README.md for more details'

setup(
    name='onedrivefb-d',
    version='0.1',
    author='Matt Wallace',
    author_email='matthew.r.wallace@live.com',
    license='GPLv3',
    keywords=[
        'onedrive', 'ondrive for business', 'microsoft', 'daemon', 'o365',
        'cloud', 'storage', 'storage provider', 'file hosting', 'skydrive'
    ],
    url='http://github.com/MattRWallace/onedrivefb-d',
    description='A Microsoft OneDrive for business daemon for Linux.',
    long_description=readme,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: X11 Applications',
        'Environment :: X11 Applications :: GTK',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
        'Topic :: Software Development',
        'Topic :: System :: Archiving',
        'Topic :: System :: Filesystems',
        'Topic :: Utilities'],
    install_requires=[
        'requests', 'urllib3', 'certifi', 'send2trash', 'daemonocle'],
    packages=find_packages(),
    include_package_data=True,
    package_data={'onedrivefb_d': ['res/*.png', 'res/*.ini']},
    exclude_package_data={'': ['README.*', 'install.sh']},
    entry_points={
        'console_scripts': [
            'onedrivefb-d = onedrivefb_d.od_main:main',
            'onedrivefb-pref = onedrivefb_d.od_pref:main'
        ]
    }
)
