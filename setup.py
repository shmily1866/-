from setuptools import setup
from Cython.Build import cythonize

setup(
    name="rate_limiter",
    ext_modules=cythonize("rate_limiter.py"),
)
