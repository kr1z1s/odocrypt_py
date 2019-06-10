#include <Python.h>

#include <ctime>
#include "odocrypt.h"
extern "C" {
#include "KeccakP-800-SnP.h"
}

#define MAINNET_EPOCH_LEN  864000
#define TESTNET_EPOCH_LEN  86400

static void odocrypt_hash(const char *input, char *output)
{
    char cipher[KeccakP800_stateSizeInBytes] = {};  
    uint32_t key; 

    key = time(NULL) - (time(NULL) % MAINNET_EPOCH_LEN);

    memcpy(cipher, input, 80);
    cipher[80] = 1;

    OdoCrypt(key).Encrypt(cipher, cipher);
    KeccakP800_Permute_12rounds(cipher);

    memcpy(output, cipher, 32);
}

static PyObject *odocrypt_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = (char *)PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    odocrypt_hash((char *)PyBytes_AsString((PyObject*) input), output);
#else
    odocrypt_hash((char *)PyString_AsString((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef OdocryptMethods[] = {
    { "getPoWHash", odocrypt_getpowhash, METH_VARARGS, "Returns the odocrypt hash for Mainnet/testnet Digibyte" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef OdocryptModule = {
    PyModuleDef_HEAD_INIT,
    "odocrypt_hash",
    "...",
    -1,
    OdocryptMethods
};

PyMODINIT_FUNC PyInit_odocrypt_hash(void) {
    return PyModule_Create(&OdocryptModule);
}

#else

PyMODINIT_FUNC initodocrypt_hash(void) {
    (void) Py_InitModule("odocrypt_hash", OdocryptMethods);
}
#endif
