from setuptools import setup, find_packages

setup(
    name="eventcollector",
    version="1.0",
    author="Neil Williams",
    author_email="neil@reddit.com",
    packages=find_packages(),
    install_requires=[
        "pyramid",
        "baseplate",
        "kafka-python",
    ],
    tests_require=[
        "mock",
    ],
    entry_points={
        "paste.app_factory": [
            "main = events.collector:make_app",
        ],
    },
)
