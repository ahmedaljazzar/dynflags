from setuptools import setup, find_packages

setup(
    name = 'dynflags',
    packages=find_packages(),
    install_requires=[
        'boto3',
        'six'
    ],
    tests_require=['moto','py>=1.5.0'],
    version='0.0.1',
    description='Scalable serverless feature flag implementation using DynamoDB',
    author='Ber Zoidberg',
    author_email='ber.zoidberg@gmail.com',
    url='https://github.com/zoidbb/dynflags',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Topic :: System :: Distributed Computing',
    ]
)
