import ctypes
import base64


class Refs:
    def __init__(self, dict):
        self.address = dict['addr']
        self.type = dict['type']
        self.at = dict['at']


class Var:
    type_defs = {'int32_t': 'int', 'uint32_t': 'u_int'}

    def __init__(self, dict):
        self.name = dict['name']
        self.kind = dict['kind']
        self.type = dict['type']
        if self.type in self.type_defs:
            self.type = self.type_defs[self.type]
        self.base = dict['ref']['base']
        self.num = dict['ref']['offset']

    @property
    def offset(self):
        if self.base == 'ebp':
            return ctypes.c_int(self.num)
        elif self.base == 'rbp':
            return ctypes.c_long(self.num)
        else:
            return self.num


class Function:
    def __init__(self, dict):
        self.address = dict['offset']
        self.name = dict['name'].replace('sym.','').replace('imp.','_')
        self.size = dict['size']
        self.realSize = dict['realsz']
        self.calltype = dict['calltype']
        self.minBound = dict['minbound']
        self.maxBound = dict['maxbound']
        self.callRefs = {}
        if 'callrefs' in dict:
            for callRef in dict['callrefs']:
                address = callRef['addr']
                at = callRef['at']
                self.callRefs[at] = address
        self.dataRefs = []
        if 'datarefs' in dict:
            self.dataRefs = dict['datarefs']
        self.codeXRefs = {}
        if 'codexrefs' in dict:
            for codeXref in dict['codexrefs']:
                address = codeXref['addr']
                at = codeXref['at']
                if at in self.codeXRefs:
                    self.codeXRefs[at].append(address)
                else:
                    self.codeXRefs[at] = [address]
        # self.numVar = dict['nlocals']
        self.numArgs = dict['nargs']
        # self.bpVars = []
        # for bvar in dict['bpvars']:
        #     self.bpVars.append(Var(bvar))
        # self.spVars = []
        # for spvar in dict['spvars']:
        #     self.spVars.append(Var(spvar))
        self.cfg = None
        self.changed = False
        self.ira = None
        self.ircfg = None
        self.defUse = None
