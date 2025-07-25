from setuptools import setup

setup(
    name='webdoxer',
    version='1.0',
    py_modules=['webdoxer'],
    entry_points={
        'console_scripts': [
            'webdoxer=webdoxer:main'
        ],
    },
    include_package_data=True
)
