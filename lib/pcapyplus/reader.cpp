/*
 * Copyright (C) 2021 Hewlett Packard Enterprise Development LP.
 * Copyright (C) 2014-2021 CORE Security Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <pcap.h>

#include "reader.hpp"
#include "pcapyplus.hpp"
#include "dumper.hpp"
#include "pkthdr.hpp"

#include <netinet/in.h>


// internal pcapobject
typedef struct {
    PyObject_HEAD
    pcap_t *pcap;
    bpf_u_int32 net;
    bpf_u_int32 mask;
} pcapobject;


// PcapType

static PyObject*
p_close(register pcapobject* pp, PyObject*)
{
    if (pp->pcap) {
        pcap_close(pp->pcap);
    }

    pp->pcap = NULL;

    Py_RETURN_NONE;
}

static void
pcap_dealloc(register pcapobject* pp)
{
    p_close(pp, NULL);

    PyObject_Del(pp);
}

static PyObject *
err_closed(void)
{
    PyErr_SetString(PyExc_ValueError, "pcap is closed");
    return NULL;
}

// pcap methods
static PyObject* p_getnet(register pcapobject* pp, PyObject* args);
static PyObject* p_getmask(register pcapobject* pp, PyObject* args);
static PyObject* p_setfilter(register pcapobject* pp, PyObject* args);
static PyObject* p_next(register pcapobject* pp, PyObject*);
static PyObject* p_dispatch(register pcapobject* pp, PyObject* args);
static PyObject* p_loop(register pcapobject* pp, PyObject* args);
static PyObject* p_datalink(register pcapobject* pp, PyObject* args);
static PyObject* p_setdirection(register pcapobject* pp, PyObject* args);
static PyObject* p_setnonblock(register pcapobject* pp, PyObject* args);
static PyObject* p_getnonblock(register pcapobject* pp, PyObject* args);
static PyObject* p_dump_open(register pcapobject* pp, PyObject* args);
static PyObject* p_sendpacket(register pcapobject* pp, PyObject* args);
static PyObject* p_stats(register pcapobject* pp, PyObject*);
static PyObject* p__enter__(register pcapobject* pp, PyObject*);
static PyObject* p_getfd(register pcapobject* pp, PyObject* args);
static PyObject* p_set_snaplen(register pcapobject* pp, PyObject* args);
static PyObject* p_set_promisc(register pcapobject* pp, PyObject* args);
static PyObject* p_set_timeout(register pcapobject* pp, PyObject* args);
static PyObject* p_set_buffer_size(register pcapobject* pp, PyObject* args);
static PyObject* p_set_rfmon(register pcapobject* pp, PyObject* args);
static PyObject* p_activate(register pcapobject* pp, PyObject* args);

static PyMethodDef p_methods[] = {
    {
        "loop", (PyCFunction) p_loop, METH_VARARGS,
        "similar to dispatch except it keeps reading packets until maxcant "
        "packets are processed or error occurs. It does not return when live read "
        "timeouts occur. Rather, specifying a non-zero read timeout to open_live "
        "and then calling dispatch allows the reception and processing of any "
        "packets that arrive when the timeout occurs. A negative maxcant causes "
        "loop to loop forever (or at least until an error occurs). 0 is returned "
        "if maxcant is exhausted."
    },

    {
        "dispatch", (PyCFunction) p_dispatch, METH_VARARGS,
        "used to collect and process packets. maxcant specifies the maximum "
        "number of packets to process before returning. This is not a minimum "
        "number; when reading a live capture, only one bufferful of packets is "
        "read at a time, so fewer than maxcant packets may be processed. A cnt of "
        "-1 processes all the packets received in one buffer when reading a live "
        "capture, or all the packets in the file when reading a savefile. "
        "callback specifies a routine to be called with two arguments: a Pkthdr "
        "instance describing the data passed and the data itself."
    },

    {
        "next", (PyCFunction) p_next, METH_NOARGS,
        "reads the next packet (by calling dispatch with a maxcant of 1) and "
        "returns a tuple (header, data) where header is a Pkthdr instance "
        "describing the data passed and data is the data itself."
    },

    {
        "setfilter", (PyCFunction) p_setfilter, METH_VARARGS,
        "used to specify a filter for this object."
    },

    {
        "getnet", (PyCFunction) p_getnet, METH_VARARGS,
        "returns the network address for the device."
    },

    {
        "getmask", (PyCFunction) p_getmask, METH_VARARGS,
        "returns the netmask for the device."
    },

    {
        "datalink", (PyCFunction) p_datalink, METH_VARARGS,
        "returns the link layer type; link layer types it can return include all "
        "the documented constant values."
    },

    {
        "getnonblock", (PyCFunction) p_getnonblock, METH_VARARGS,
        "returns the current non-blocking state of the capture descriptor; it "
        "always returns 0 on savefiles."
    },

    {
        "setnonblock", (PyCFunction) p_setnonblock, METH_VARARGS,
        "a capture descriptor, opened with open_live, into non-blocking mode, or "
        "takes it out of non-blocking mode, depending on whether the state "
        "argument is non-zero or zero. It has no effect on savefiles. In "
        "non-blocking mode, an attempt to read from the capture descriptor with "
        "dispatch will, if no packets are currently available to be read, return "
        "0 immediately rather than blocking waiting for packets to arrive. loop "
        "and next will not work in non-blocking mode."
    },

    {
        "setdirection", (PyCFunction) p_setdirection, METH_VARARGS,
        "set the direction for which packets will be captured."
    },

    {
        "dump_open", (PyCFunction) p_dump_open, METH_VARARGS,
        "called to open a savefile for writing and associate it "
        "to a newly created Dumper instance. The name - is a synonym for stdout. "
        "filename specifies the name of the file to open."
    },

    {
        "sendpacket", (PyCFunction) p_sendpacket, METH_VARARGS,
        "sends a packet through the interface"
    },

    {
        "stats", (PyCFunction) p_stats, METH_NOARGS,
        "returns statistics on the current capture as a tuple "
        "(recv, drop, ifdrop)."
    },

    {
        "close", (PyCFunction) p_close, METH_NOARGS,
        "closes a Dumper."
    },

    {
        "set_snaplen", (PyCFunction)p_set_snaplen, METH_VARARGS,
        "sets the snapshot length to be used on a capture handle "
        "when the handle is activated to snaplen. set_snaplen returns 0 on "
        "success or PCAP_ERROR_ACTIVATED if called on a capture handle that has "
        "been activated."
    },

    {
        "set_promisc", (PyCFunction)p_set_promisc, METH_VARARGS,
        "sets whether promiscuous mode should be set on a capture handle when the "
        "handle is activated. If promisc is non-zero, promiscuous mode will be "
        "set, otherwise it will not be set. set_promisc returns 0 on success or "
        "PCAP_ERROR_ACTIVATED if called on a capture handle that has been "
        "activated."
    },

    {
        "set_timeout", (PyCFunction)p_set_timeout, METH_VARARGS,
        "sets the read timeout that will be used on a capture handle when the "
        "handle is activated to to_ms, which is in units of milliseconds. "
        "Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture "
        "handle that has been activated."
    },

    {
        "set_buffer_size", (PyCFunction)p_set_buffer_size, METH_VARARGS,
        "sets the buffer size that will be used on a capture handle when the "
        "handle is activated to buffer_size, which is in units of bytes. "
        "Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture "
        "handle that has been activated."
    },

    {
        "activate", (PyCFunction)p_activate, METH_NOARGS,
        "is used to activate a packet capture handle to look at packets on the "
        "network, with the options that were set on the handle being in effect. "
        "Returns 0 on success without warnings, a non-zero positive value on "
        "success with warnings, and a negative value on error. A non-zero return "
        "value indicates what warning or error condition occurred."
    },

    {"__enter__", (PyCFunction) p__enter__, METH_NOARGS, NULL},
    {"__exit__", (PyCFunction) p_close, METH_VARARGS, NULL},

    {
        "getfd", (PyCFunction) p_getfd, METH_VARARGS,
        "returns, on UNIX, a file descriptor number for a file descriptor on "
        "which one can do a select, poll, epoll_wait, kevent, or other such call "
        "to wait for it to be possible to read packets without blocking, if such "
        "a descriptor exists, or -1, if no such descriptor exists."
    },

    {
        /* Available on Npcap, not on Winpcap. */
        "set_rfmon", (PyCFunction)p_set_rfmon, METH_VARARGS,
        "set monitor mode for a not-yet-activated capture handle."
    },

    {NULL, NULL} /* sentinel */
};

static PyObject* pcap_getattr(pcapobject* pp, char* name)
{
    PyObject *nameobj = PyUnicode_FromString(name);
    PyObject *attr = PyObject_GenericGetAttr((PyObject *)pp, nameobj);
    Py_DECREF(nameobj);
    return attr;
}


PyTypeObject Pcaptype = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "Reader",                /* tp_name */
    sizeof(pcapobject),      /* tp_basicsize */
    0,                       /* tp_itemsize */
    (destructor)pcap_dealloc, /* tp_dealloc */
    0,                       /* tp_print */
    (getattrfunc)pcap_getattr, /* tp_getattr */
    0,                       /* tp_setattr */
    0,                       /* tp_reserved */
    0,                       /* tp_repr */
    0,                       /* tp_as_number */
    0,                       /* tp_as_sequence */
    0,                       /* tp_as_mapping */
    0,                       /* tp_hash */
    0,                       /* tp_call */
    0,                       /* tp_str */
    0,                       /* tp_getattro */
    0,                       /* tp_setattro */
    0,                       /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,      /* tp_flags */
    NULL,                    /* tp_doc */
    0,                       /* tp_traverse */
    0,                       /* tp_clear */
    0,                       /* tp_richcompare */
    0,                       /* tp_weaklistoffset */
    0,                       /* tp_iter */
    0,                       /* tp_iternext */
    p_methods,               /* tp_methods */
    0,                       /* tp_members */
    0,                       /* tp_getset */
    0,                       /* tp_base */
    0,                       /* tp_dict */
    0,                       /* tp_descr_get */
    0,                       /* tp_descr_set */
    0,                       /* tp_dictoffset */
    0,                       /* tp_init */
    0,                       /* tp_alloc */
    0,                       /* tp_new */
};


PyObject* new_pcapobject(pcap_t *pcap, bpf_u_int32 net, bpf_u_int32 mask)
{
    if (PyType_Ready(&Pcaptype) < 0) {
        return NULL;
    }

    pcapobject *pp;

    pp = PyObject_New(pcapobject, &Pcaptype);
    if (pp == NULL) {
        return NULL;
    }

    pp->pcap = pcap;
    pp->net = net;
    pp->mask = mask;

    return (PyObject*)pp;
}

static void ntos(char* dst, unsigned int n, int ip)
{
    ip = htonl(ip);
    snprintf(dst, n, "%i.%i.%i.%i",
             ((ip >> 24) & 0xFF),
             ((ip >> 16) & 0xFF),
             ((ip >> 8) & 0xFF),
             (ip & 0xFF));
}

static PyObject* p_getnet(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    char ip_str[20];
    ntos(ip_str, sizeof(ip_str), pp->net);
    return Py_BuildValue("s", ip_str);
}

static PyObject* p_getmask(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    char ip_str[20];
    ntos(ip_str, sizeof(ip_str), pp->mask);
    return Py_BuildValue("s", ip_str);
}

static PyObject* p_setfilter(register pcapobject* pp, PyObject* args)
{
    struct bpf_program bpfprog;
    int status;
    char* str;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    if (!PyArg_ParseTuple(args,"s:setfilter",&str)) {
        return NULL;
    }

    status = pcap_compile(pp->pcap, &bpfprog, str, 1, pp->mask);
    if (status) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }

    status = pcap_setfilter(pp->pcap, &bpfprog);
    if (status) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* p_next(register pcapobject* pp, PyObject*)
{
    struct pcap_pkthdr *hdr = NULL;
    const unsigned char *buf = (const unsigned char*)"";
    int err_code = 1;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    // allow threads as this might block
    Py_BEGIN_ALLOW_THREADS;
    err_code = pcap_next_ex(pp->pcap, &hdr, &buf);
    Py_END_ALLOW_THREADS;

    if (err_code == -1) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }


    PyObject *pkthdr;
    int _caplen = 0;
    if (err_code == 1) {
        pkthdr = new_pcap_pkthdr(hdr);
        _caplen = hdr->caplen;
    } else {
        pkthdr = Py_None;
        Py_INCREF(pkthdr);
        _caplen = 0;
    }


    if (pkthdr) {
        PyObject *ret = NULL;

        /* return bytes */
        ret = Py_BuildValue("(Oy#)", pkthdr, buf, _caplen);

        Py_DECREF(pkthdr);
        return ret;
    }

    PyErr_SetString(PcapError, "Can't build pkthdr");
    return NULL;
}

struct PcapCallbackContext {
    PcapCallbackContext(pcap_t* p, PyObject* f, PyThreadState* ts)
        : ppcap_t(p), pyfunc(f), thread_state(ts)
    {
        Py_INCREF(pyfunc);
    }
    ~PcapCallbackContext()
    {
        Py_DECREF(pyfunc);
    }

    pcap_t* ppcap_t;
    PyObject *pyfunc;
    PyThreadState *thread_state;
};


static void PythonCallBack(u_char *user,
               const struct pcap_pkthdr *header,
               const u_char *packetdata)
{
    PyObject *arglist, *result;
    unsigned int *len;
    PcapCallbackContext *pctx;
    len = (unsigned int *)&header->caplen;
    pctx = (PcapCallbackContext *)user;

    PyEval_RestoreThread(pctx->thread_state);

    PyObject *hdr = new_pcap_pkthdr(header);

    /* pass bytes */
    arglist = Py_BuildValue("Oy#", hdr, packetdata, *len);

    result = PyEval_CallObject(pctx->pyfunc,arglist);

    Py_XDECREF(arglist);
    if (result) {
        Py_DECREF(result);
    }

    Py_DECREF(hdr);

    if (!result) {
        pcap_breakloop(pctx->ppcap_t);
    }

    PyEval_SaveThread();
}

static PyObject* p_dispatch(register pcapobject* pp, PyObject* args)
{
    int cant, ret;
    PyObject *PyFunc;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    if (!PyArg_ParseTuple(args,"iO:dispatch",&cant,&PyFunc)) {
        return NULL;
    }

    PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
    PyEval_SaveThread();
    ret = pcap_dispatch(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
    PyEval_RestoreThread(ctx.thread_state);

    if (ret < 0) {
        if (ret != -2) {
            /* pcap error, pcap_breakloop was not called so error is not set */
            PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        }
        return NULL;
    }

    return Py_BuildValue("i", ret);
}

static PyObject* p_stats(register pcapobject* pp, PyObject*)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    struct pcap_stat stats;

    if (-1 == pcap_stats(pp->pcap, &stats)) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }

    return Py_BuildValue("III", stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
}

static PyObject* p__enter__(register pcapobject* pp, PyObject*)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    Py_INCREF(pp);
    return (PyObject*)pp;
}

static PyObject* p_dump_open(register pcapobject* pp, PyObject* args)
{
    char *filename;
    pcap_dumper_t *ret;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    if (!PyArg_ParseTuple(args,"s",&filename)) {
        return NULL;
    }

    ret = pcap_dump_open(pp->pcap, filename);

    if (ret == NULL) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }

    return new_pcapdumper(ret);
}


static PyObject* p_loop(register pcapobject* pp, PyObject* args)
{
    int cant, ret;
    PyObject *PyFunc;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    if (!PyArg_ParseTuple(args,"iO:loop",&cant,&PyFunc)) {
        return NULL;
    }

    PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
    PyEval_SaveThread();
    ret = pcap_loop(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
    PyEval_RestoreThread(ctx.thread_state);

    if (ret < 0) {
        if (ret != -2) {
            /* pcap error, pcap_breakloop was not called so error is not set */
            PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        }
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject* p_datalink(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int type = pcap_datalink(pp->pcap);

    return Py_BuildValue("i", type);
}

static PyObject* p_setdirection(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    pcap_direction_t direction;

    if (!PyArg_ParseTuple(args, "i", &direction)) {
        return NULL;
    }

    int ret = pcap_setdirection(pp->pcap, direction);
    if (-1 == ret) {
        PyErr_SetString(PcapError, "Failed setting direction");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* p_setnonblock(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int state;

    if (!PyArg_ParseTuple(args, "i", &state)) {
        return NULL;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    int ret = pcap_setnonblock(pp->pcap, state, errbuf);
    if (-1 == ret) {
        PyErr_SetString(PcapError, errbuf);
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* p_getnonblock(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    int state = pcap_getnonblock(pp->pcap, errbuf);
    if (-1 == state) {
        PyErr_SetString(PcapError, errbuf);
        return NULL;
    }

    return Py_BuildValue("i", state);
}

static PyObject* p_set_snaplen(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int snaplen;

    if (!PyArg_ParseTuple(args, "i", &snaplen)) {
        return NULL;
    }

    int ret = pcap_set_snaplen(pp->pcap, snaplen);
    return Py_BuildValue("i", ret);
}

static PyObject* p_set_promisc(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int promisc;

    if (!PyArg_ParseTuple(args, "i", &promisc)) {
        return NULL;
    }

    int ret = pcap_set_promisc(pp->pcap, promisc);
    return Py_BuildValue("i", ret);
}

static PyObject* p_set_timeout(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int to_ms;

    if (!PyArg_ParseTuple(args, "i", &to_ms)) {
        return NULL;
    }

    int ret = pcap_set_timeout(pp->pcap, to_ms);
    return Py_BuildValue("i", ret);
}

static PyObject* p_set_buffer_size(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int buffer_size;

    if (!PyArg_ParseTuple(args, "i", &buffer_size)) {
        return NULL;
    }

    int ret = pcap_set_buffer_size(pp->pcap, buffer_size);
    return Py_BuildValue("i", ret);
}

static PyObject* p_set_rfmon(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int rfmon;

    if (!PyArg_ParseTuple(args, "i", &rfmon)) {
        return NULL;
    }

    int ret = pcap_set_rfmon(pp->pcap, rfmon);
    return Py_BuildValue("i", ret);
}

static PyObject* p_activate(register pcapobject* pp, PyObject*)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int ret = pcap_activate(pp->pcap);
    return Py_BuildValue("i", ret);
}


static PyObject* p_sendpacket(register pcapobject* pp, PyObject* args)
{
    int status;
    unsigned char* str;
    Py_ssize_t length;
    int native_length;

    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    /* accept bytes */
    if (!PyArg_ParseTuple(args,"y#", &str, &length)) {
        return NULL;
    }

    // Support for PEP-0353
    // https://www.python.org/dev/peps/pep-0353/#conversion-guidelines
    native_length = Py_SAFE_DOWNCAST(length, Py_ssize_t, int);

    status = pcap_sendpacket(pp->pcap, str, native_length);
    if (status) {
        PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject* p_getfd(register pcapobject* pp, PyObject* args)
{
    if (Py_TYPE(pp) != &Pcaptype) {
        PyErr_SetString(PcapError, "Not a pcap object");
        return NULL;
    }

    if (!pp->pcap) {
        return err_closed();
    }

    int fd = pcap_get_selectable_fd(pp->pcap);
    return Py_BuildValue("i", fd);
}