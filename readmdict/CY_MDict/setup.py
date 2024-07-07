from distutils.core import setup
from Cython.Build import cythonize
setup(name='MDict',
      ext_modules=cythonize("MDict.pyx"))