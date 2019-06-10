from distutils.core import setup, Extension

odocrypt_hash_module = Extension('odocrypt_hash', sources = ['odocryptmodule.cpp', 
															'odocrypt.cpp',
															'KeccakP-800-reference.c'],
												extra_compile_args=['-march=native', '-Ofast', '-mtune=native', '-pipe'])

setup (name = 'odocrypt_hash',
       version = '0.1',
       ext_modules = [odocrypt_hash_module])
