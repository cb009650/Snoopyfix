from setuptools import setup

setup(
    name='snoopyfix',
    version='1.0',
    py_modules=['snoopyfix','misconfig'],
    entry_points={
        'console_scripts': [
            'snoopyfix = snoopyfix:main',
        ],
    },
  
)