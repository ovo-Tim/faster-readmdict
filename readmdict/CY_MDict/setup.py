from distutils.core import setup
from Cython.Build import cythonize
import shutil
setup(name='MDict',
      ext_modules=cythonize("readmdict/CY_MDict/MDict.pyx",  build_dir=""),
      script_args=['build_ext'],
      options={'build_ext': {'inplace': False, 'build_lib': "readmdict/CY_MDict"}})