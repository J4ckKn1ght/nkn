from future.utils import viewitems
from future.utils import viewvalues
from miasm.analysis.data_flow import load_from_int
from miasm.analysis.simplifier import IRCFGSimplifierCommon, IRCFGSimplifierSSA
from miasm.analysis.ssa import SSADiGraph
from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprLoc, ExprOp, ExprSlice, ExprCond, LocKey
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.analysis.data_flow import DiGraphDefUse, ReachingDefinitions
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine

from Analysis import BinaryAnalysis


def parseExpr(expr, result):
    if isinstance(expr, ExprId):
        result.append(expr)
    elif isinstance(expr, ExprMem):
        result.append(expr)
    elif isinstance(expr, ExprInt):
        result.append(expr)
    elif isinstance(expr, ExprLoc):
        result.append(expr)
    elif isinstance(expr, ExprOp):
        if len(expr.args) == 1:
            result.append(expr.op)
            result.append('(')
            result = parseExpr(expr.args[0], result)
            result.append(')')
        else:
            exprStr = str(expr)
            if exprStr.index(expr.op) == 0:
                result.append(expr.op)
                result.append('(')
                count = 0
                for arg in expr.args:
                    result = parseExpr(arg, result)
                    if count != len(expr.args) - 1:
                        result.append(',')
                    count += 1
                result.append(')')
            else:
                count = 0
                for e in expr.args:
                    if count == 1:
                        result.append(expr.op)
                    result = parseExpr(e, result)
                    count += 1
    elif isinstance(expr, ExprSlice):
        if isinstance(expr.arg, ExprId) or isinstance(expr.arg, ExprMem):
            result.append(expr)
        else:
            result = parseExpr(expr.arg, result)
            result.append('[%d:%d]' % (expr.start, expr.stop))
    elif isinstance(expr, ExprCond):
        result.append('(')
        result = parseExpr(expr.cond, result)
        result.append(')')
        result.append('?')
        result.append('(')
        result.append(expr.src1)
        result.append(',')
        result.append(expr.src2)
        result.append(')')
    else:
        result.append(expr)
    return result


def is_addr_ro_variable(bs, addr, size):
    try:
        _ = bs.getbytes(addr, size // 8)
    except IOError:
        return False
    return True


class IRADelModCallStack(BinaryAnalysis.iraType):

    def call_effects(self, addr, instr):
        assignblks, extra = super(IRADelModCallStack, self).call_effects(addr, instr)
        out = []
        for assignblk in assignblks:
            dct = dict(assignblk)
            dct = {
                dst: src for (dst, src) in viewitems(dct) if dst != self.sp
            }
            out.append(AssignBlock(dct, assignblk.instr))
        return out, extra


class IRAOutRegs(BinaryAnalysis.iraType):
    def get_out_regs(self, block):
        regs_todo = super(self.__class__, self).get_out_regs(block)
        out = {}
        for assignblk in block:
            for dst in assignblk:
                reg = self.ssa_var.get(dst, None)
                if reg is None:
                    continue
                if reg in regs_todo:
                    out[reg] = dst
        return set(viewvalues(out))


class CustomIRCFGSimplifierSSA(IRCFGSimplifierSSA):
    def do_simplify(self, ssa, head):
        modified = super(CustomIRCFGSimplifierSSA, self).do_simplify(ssa, head)
        modified |= load_from_int(ssa.graph, BinaryAnalysis.container.bin_stream, is_addr_ro_variable)

    def simplify(self, ircfg, head):
        ssa = self.ircfg_to_ssa(ircfg, head)
        ssa = self.do_simplify_loop(ssa, head)
        ircfg = self.ssa_to_unssa(ssa, head)
        ircfg_simplifier = IRCFGSimplifierCommon(self.ir_arch)
        ircfg_simplifier.simplify(ircfg, head)
        return ircfg


class IRAnalysis:
    def __init__(self, address, cfg):
        self.rawIRA = BinaryAnalysis.iraType(cfg.loc_db)
        self.normalIRA = BinaryAnalysis.iraType(cfg.loc_db)
        self.ssaIRA = IRADelModCallStack(cfg.loc_db)
        self.maxIRA1 = IRADelModCallStack(cfg.loc_db)
        self.maxIRA2 = IRAOutRegs(cfg.loc_db)
        self.rawIRCFG = self.rawIRA.new_ircfg_from_asmcfg(cfg)
        self.normalIRCFG = None
        self.ssaIRCFG = None
        self.maxIRCFG = None
        self.rawDefUse = DiGraphDefUse(ReachingDefinitions(self.rawIRCFG))
        self.normalDefUse = None
        self.ssaDefUse = None
        self.maxDefUse = None
        self.head = cfg.loc_db.get_offset_location(address)
        self.address = address
        self.cfg = cfg

    def getRawIRCFG(self):
        return self.rawIRCFG

    def getNormalIRCFG(self):
        if self.normalIRCFG is not None:
            return self.normalIRCFG
        else:
            self.normalIRCFG = self.normalIRA.new_ircfg_from_asmcfg(self.cfg)
            simplifier = IRCFGSimplifierCommon(self.normalIRA)
            simplifier.simplify(self.normalIRCFG, self.head)
            self.normalDefUse = DiGraphDefUse(ReachingDefinitions(self.normalIRCFG))
            return self.normalIRCFG

    def getSSAIRCFG(self):
        if self.ssaIRCFG is not None:
            return self.ssaIRCFG
        else:
            self.ssaIRCFG = self.ssaIRA.new_ircfg_from_asmcfg(self.cfg)
            simplifier = IRCFGSimplifierCommon(self.ssaIRA)
            simplifier.simplify(self.ssaIRCFG, self.head)
            ssa = SSADiGraph(self.ssaIRCFG)
            ssa.transform(self.head)
            self.ssaDefUse = DiGraphDefUse(ReachingDefinitions(self.ssaIRCFG))
            return self.ssaIRCFG

    def getMaxIRCFG(self):
        if self.maxIRCFG is not None:
            return self.maxIRCFG
        else:
            self.maxIRCFG = self.maxIRA1.new_ircfg_from_asmcfg(self.cfg)
            simplifier = IRCFGSimplifierCommon(self.maxIRA1)
            simplifier.simplify(self.maxIRCFG, self.head)
            for loc in self.maxIRCFG.leaves():
                irblock = self.maxIRCFG.blocks.get(loc)
                if irblock is None:
                    continue
                regs = {}
                for reg in self.maxIRA1.get_out_regs(irblock):
                    regs[reg] = reg
                assignblks = list(irblock)
                newAssignBlk = AssignBlock(regs, assignblks[-1].instr)
                assignblks.append(newAssignBlk)
                newIrBlock = IRBlock(irblock.loc_key, assignblks)
                self.maxIRCFG.blocks[loc] = newIrBlock
            simplifier = CustomIRCFGSimplifierSSA(self.maxIRA2)
            simplifier.simplify(self.maxIRCFG, self.head)
            self.maxDefUse = DiGraphDefUse(ReachingDefinitions(self.maxIRCFG))
            return self.maxIRCFG

    def getRawDefUse(self):
        return self.rawDefUse

    def getNormalDefUse(self):
        if self.normalDefUse is None:
            self.getNormalIRCFG()
        return self.normalDefUse

    def getSSADefUse(self):
        if self.ssaIRCFG is None:
            self.getSSAIRCFG()
        return self.ssaDefUse

    def getMaxDefUse(self):
        if self.maxDefUse is None:
            self.getMaxIRCFG()
        return self.maxDefUse

    def getRawIRA(self):
        return self.rawIRA

    def getNormalIRA(self):
        if self.normalIRCFG is None:
            self.getNormalIRCFG()
        return self.normalIRA

    def getSSAIRA(self):
        if self.ssaIRCFG is None:
            self.getSSAIRCFG()
        return self.ssaIRA

    def getMaxIRA(self):
        if self.maxIRCFG is None:
            self.getMaxIRCFG()
        return self.maxIRA2

    def recoverAlgorithm(self):
        if self.normalIRCFG is None:
            self.getNormalIRCFG()
        newLocDB = LocationDB()
        size = BinaryAnalysis.disasmEngine.attrib
        newIRA = BinaryAnalysis.iraType(newLocDB)
        newIRCFG = newIRA.new_ircfg()
        numLockey = 0
        head = LocKey(numLockey)
        todo = [(self.address, head, {}, None)]
        numLockey += 1
        while todo:
            nextTarget, lockey, state, preBlock = todo.pop()
            nextTarget, state= self.symbolicExecution(self.normalIRA, self.normalIRCFG, nextTarget, state)
            if isinstance(nextTarget, ExprCond):
                newLockey1 = LocKey(numLockey)
                newLockey2 = LocKey(numLockey + 1)
                ir_dst = state[newIRCFG.IRDst]
                new_cond = ExprCond(ir_dst.cond, ExprLoc(newLockey1, size), ExprLoc(newLockey2, size))
                state[newIRCFG.IRDst] = new_cond
                numLockey += 2
                newIRBlock = self.addIRBlock(newIRCFG, state, lockey)
                state[newIRCFG.IRDst] = ir_dst
                todo.append((nextTarget.src1, newLockey1, state, newIRBlock))
                todo.append((nextTarget.src2, newLockey2, state, newIRBlock))
            else:
                self.addIRBlock(newIRCFG, state, lockey)
        return newLocDB, newIRCFG

    def addIRBlock(self, newIRCFG, state, lockey):
        assignBlocks = []
        lastAssign = None
        lastIndex = None
        for dst, src in state.items():
            newAssign = AssignBlock({dst: src})
            if dst == newIRCFG._irdst:
                lastAssign = newAssign
                lastIndex = len(assignBlocks)
            assignBlocks.append(newAssign)
        tmp = assignBlocks[-1]
        assignBlocks[-1] = lastAssign
        assignBlocks[lastIndex] = tmp
        newIRBlock = IRBlock(lockey, assignBlocks)
        newIRCFG.add_irblock(newIRBlock)
        return newIRBlock

    def symbolicExecution(self, ira, ircfg, address, state):
        symbolicEngine = SymbolicExecutionEngine(ira, state)
        nextTarget = symbolicEngine.run_block_at(ircfg, address)
        while not isinstance(nextTarget, ExprCond) and not isinstance(nextTarget, ExprMem):
            nextTarget = symbolicEngine.run_block_at(ircfg, nextTarget, step=False)
        return nextTarget, symbolicEngine.symbols

