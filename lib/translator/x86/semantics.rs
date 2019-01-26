use falcon_capstone::capstone;
use falcon_capstone::capstone::cs_x86_op;
use falcon_capstone::capstone_sys::{x86_op_type, x86_reg};
use error::*;
use il::*;
use il::Expression as Expr;
use translator::x86::x86register::*;
use translator::x86::Mode;


pub(crate) struct Semantics<'s> {
    mode: &'s Mode,
    instruction: &'s capstone::Instr
}

impl<'s> Semantics<'s> {
    pub fn new(mode: &'s Mode, instruction: &'s capstone::Instr) -> Semantics<'s> {
        Semantics {
            mode: mode,
            instruction: instruction
        }
    }

    pub fn instruction(&self) -> &capstone::Instr {
        &self.instruction
    }


    pub fn mode(&self) -> &Mode {
        &self.mode
    }


    /// Returns the details section of an x86 capstone instruction.
    pub fn details(&self) -> Result<capstone::cs_x86> {

        let detail = self.instruction().detail.as_ref().unwrap();

        match detail.arch {
            capstone::DetailsArch::X86(x) => Ok(x),
            _ => Err("Could not get instruction details".into())
        }
    }


    pub fn operand_load(&self, mut block: &mut Block, operand: &cs_x86_op)
        -> Result<Expression> {
        
        self.mode.operand_load(&mut block, operand, self.instruction())
    }


    pub fn operand_store(
        &self,
        mut block: &mut Block,
        operand: &cs_x86_op,
        value: Expression
    ) -> Result<()> {

        self.mode.operand_store(&mut block, operand, value, self.instruction())
    }

    pub fn get_register(&self, capstone_id: x86_reg)
        -> Result<&'static X86Register> {

        self.mode.get_register(capstone_id)
    }

    /// Convenience function set set the zf based on result
    pub fn set_zf(&self, block: &mut Block, result: Expression) -> Result<()> {
        let expr = Expr::cmpeq(result.clone(), expr_const(0, result.bits()))?;
        block.assign(scalar("ZF", 1), expr);
        Ok(())
    }


    /// Convenience function to set the sf based on result
    pub fn set_sf(&self, block: &mut Block, result: Expression) -> Result<()> {
        let expr = Expr::shr(result.clone(),
                             expr_const((result.bits() - 1) as u64,
                             result.bits()))?;
        let expr = Expr::trun(1, expr)?;
        block.assign(scalar("SF", 1), expr);
        Ok(())
    }


    /// Convenience function to set the of based on result and both operands
    pub fn set_of(
        &self,
        block: &mut Block,
        result: Expression,
        lhs: Expression,
        rhs: Expression
    ) -> Result<()> {

        let expr0 = Expr::xor(lhs.clone().into(), rhs.clone().into())?;
        let expr1 = Expr::xor(lhs.clone().into(), result.clone().into())?;
        let expr = Expr::and(expr0, expr1)?;
        let expr = Expr::shr(expr.clone(),
                             expr_const((expr.bits() - 1) as u64,
                                expr.bits()))?;
        block.assign(scalar("OF", 1), Expr::trun(1, expr)?);
        Ok(())
    }


    /// Convenience function to set the cf based on result and lhs operand
    pub fn set_cf(&self, block: &mut Block, result: Expression, lhs: Expression)
        -> Result<()> {

        let expr = Expr::cmpltu(lhs.clone().into(), result.clone().into())?;
        block.assign(scalar("CF", 1), expr);
        Ok(())
    }


    /// Returns a condition which is true if a conditional instruction should be
    /// executed. Used for setcc, jcc and cmovcc.
    pub fn cc_condition(&self) -> Result<Expression> {
        if let capstone::InstrIdArch::X86(instruction_id) = self.instruction().id {
            match instruction_id {
                capstone::x86_insn::X86_INS_CMOVA |
                capstone::x86_insn::X86_INS_JA |
                capstone::x86_insn::X86_INS_SETA => {
                    let cf = Expr::cmpeq(expr_scalar("CF", 1),
                                         expr_const(0, 1))?;
                    let zf = Expr::cmpeq(expr_scalar("ZF", 1),
                                         expr_const(0, 1))?;
                    Expr::and(cf, zf)
                },
                capstone::x86_insn::X86_INS_CMOVAE |
                capstone::x86_insn::X86_INS_JAE |
                capstone::x86_insn::X86_INS_SETAE =>
                    Expr::cmpeq(expr_scalar("CF", 1), expr_const(0, 1)),
                capstone::x86_insn::X86_INS_CMOVB |
                capstone::x86_insn::X86_INS_JB |
                capstone::x86_insn::X86_INS_SETB =>
                    Expr::cmpeq(expr_scalar("CF", 1), expr_const(1, 1)),
                capstone::x86_insn::X86_INS_CMOVBE |
                capstone::x86_insn::X86_INS_JBE |
                capstone::x86_insn::X86_INS_SETBE => {
                    let cf = Expr::cmpeq(expr_scalar("CF", 1),
                                         expr_const(1, 1))?;
                    let zf = Expr::cmpeq(expr_scalar("ZF", 1),
                                         expr_const(1, 1))?;
                    Expr::or(cf, zf)
                },
                capstone::x86_insn::X86_INS_JCXZ => {
                    let cx = self.get_register(x86_reg::X86_REG_CX)?.get()?;
                    Expr::cmpeq(cx, expr_const(0, 16))
                },
                capstone::x86_insn::X86_INS_JECXZ => {
                    let cx = self.get_register(x86_reg::X86_REG_ECX)?.get()?;
                    Expr::cmpeq(cx, expr_const(0, 32))
                },
                capstone::x86_insn::X86_INS_CMOVE |
                capstone::x86_insn::X86_INS_JE |
                capstone::x86_insn::X86_INS_SETE =>
                    Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1)),
                capstone::x86_insn::X86_INS_CMOVG |
                capstone::x86_insn::X86_INS_JG |
                capstone::x86_insn::X86_INS_SETG => {
                    let sfof = Expr::cmpeq(expr_scalar("SF", 1),
                                           expr_scalar("OF", 1))?;
                    let zf = Expr::cmpeq(expr_scalar("ZF", 1),
                                         expr_const(0, 1))?;
                    Expr::and(sfof, zf)
                },
                capstone::x86_insn::X86_INS_CMOVGE |
                capstone::x86_insn::X86_INS_JGE |
                capstone::x86_insn::X86_INS_SETGE =>
                    Expr::cmpeq(expr_scalar("SF", 1), expr_scalar("OF", 1)),
                capstone::x86_insn::X86_INS_CMOVL |
                capstone::x86_insn::X86_INS_JL |
                capstone::x86_insn::X86_INS_SETL =>
                    Expr::cmpneq(expr_scalar("SF", 1), expr_scalar("OF", 1)),
                capstone::x86_insn::X86_INS_CMOVLE |
                capstone::x86_insn::X86_INS_JLE |
                capstone::x86_insn::X86_INS_SETLE => {
                    let sfof = Expr::cmpneq(expr_scalar("SF", 1),
                                            expr_scalar("OF", 1))?;
                    let zf = Expr::cmpeq(expr_scalar("ZF", 1),
                                         expr_const(1, 1))?;
                    Expr::or(sfof, zf)
                },
                capstone::x86_insn::X86_INS_CMOVNE |
                capstone::x86_insn::X86_INS_JNE |
                capstone::x86_insn::X86_INS_SETNE =>
                    Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1)),
                capstone::x86_insn::X86_INS_CMOVNO |
                capstone::x86_insn::X86_INS_JNO |
                capstone::x86_insn::X86_INS_SETNO =>
                    Expr::cmpeq(expr_scalar("OF", 1), expr_const(0, 1)),
                capstone::x86_insn::X86_INS_CMOVNP |
                capstone::x86_insn::X86_INS_JNP |
                capstone::x86_insn::X86_INS_SETNP =>
                    Expr::cmpeq(expr_scalar("PF", 1), expr_const(0, 1)),
                capstone::x86_insn::X86_INS_CMOVNS |
                capstone::x86_insn::X86_INS_JNS |
                capstone::x86_insn::X86_INS_SETNS =>
                    Expr::cmpeq(expr_scalar("SF", 1), expr_const(0, 1)),
                capstone::x86_insn::X86_INS_CMOVO |
                capstone::x86_insn::X86_INS_JO |
                capstone::x86_insn::X86_INS_SETO  =>
                    Expr::cmpeq(expr_scalar("OF", 1), expr_const(1, 1)),
                capstone::x86_insn::X86_INS_CMOVP |
                capstone::x86_insn::X86_INS_JP |
                capstone::x86_insn::X86_INS_SETP  =>
                    Expr::cmpeq(expr_scalar("PF", 1), expr_const(1, 1)),
                capstone::x86_insn::X86_INS_CMOVS |
                capstone::x86_insn::X86_INS_JS |
                capstone::x86_insn::X86_INS_SETS  =>
                    Expr::cmpeq(expr_scalar("SF", 1), expr_const(1, 1)),
                _ => bail!("unhandled jcc")
            }
        }
        else {
            bail!("not an x86 instruction")
        }
    }


    /// Returns a condition which is true if a loop should be taken
    pub fn loop_condition(&self)-> Result<Expression> {

        let cx = self.get_register(x86_reg::X86_REG_ECX)?.get_full()?;

        if let capstone::InstrIdArch::X86(instruction_id) = self.instruction().id {
            match instruction_id {
                capstone::x86_insn::X86_INS_LOOP =>
                    Expr::cmpneq(cx.get()?, expr_const(0, cx.bits())),
                capstone::x86_insn::X86_INS_LOOPE => {
                    let expr = Expr::cmpneq(cx.get()?,
                                            expr_const(0, cx.bits()))?;
                    Expr::and(expr, Expr::cmpeq(expr_scalar("ZF", 1),
                                                expr_const(1, 1))?)
                }
                capstone::x86_insn::X86_INS_LOOPNE => {
                    let expr = Expr::cmpneq(cx.get()?,
                                            expr_const(0, cx.bits()))?;
                    Expr::and(expr, Expr::cmpeq(expr_scalar("ZF", 1),
                                                expr_const(0, 1))?)
                }
                _ => bail!("unhandled loop")
            }
        }
        else {
            bail!("not an x86 instruction")
        }
    }


    /// Wraps the given instruction graph with the rep prefix inplace
    pub fn rep_prefix(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        if    control_flow_graph.entry().is_none()
           || control_flow_graph.exit().is_none() {
            bail!("control_flow_graph entry/exit was none");
        }

        let cx = self.get_register(x86_reg::X86_REG_ECX)?.get_full()?;

        let head_index = control_flow_graph.new_block()?.index();

        let loop_index = {
            let mut loop_block = control_flow_graph.new_block()?;
            cx.set(&mut loop_block,
                   Expr::sub(cx.get()?, expr_const(1, self.mode().bits()))?)?;
            loop_block.index()
        };

        let terminating_index = control_flow_graph.new_block()?.index();

        let entry = control_flow_graph.entry().clone().unwrap();
        let exit = control_flow_graph.exit().clone().unwrap();

        // head -> entry
        // head -> terminating
        control_flow_graph.conditional_edge(
            head_index,
            entry,
            Expr::cmpneq(cx.get()?, expr_const(0, self.mode().bits()))?
        )?;
        control_flow_graph.conditional_edge(
            head_index,
            terminating_index,
            Expr::cmpeq(cx.get()?, expr_const(0, self.mode().bits()))?
        )?;

        // exit -> loop
        control_flow_graph.unconditional_edge(exit, loop_index)?;

        if let capstone::InstrIdArch::X86(instruction_id) = self.instruction().id {
            match instruction_id {
                capstone::x86_insn::X86_INS_CMPSB |
                capstone::x86_insn::X86_INS_CMPSW |
                capstone::x86_insn::X86_INS_CMPSD |
                capstone::x86_insn::X86_INS_CMPSQ |
                capstone::x86_insn::X86_INS_SCASB |
                capstone::x86_insn::X86_INS_SCASW |
                capstone::x86_insn::X86_INS_SCASD |
                capstone::x86_insn::X86_INS_SCASQ => {
                    // loop -> head
                    control_flow_graph.conditional_edge(
                        loop_index,
                        head_index,
                        Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1))?
                    )?;
                    // loop -> terminating
                    control_flow_graph.conditional_edge(
                        loop_index,
                        terminating_index,
                        Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1))?
                    )?;
                },
                capstone::x86_insn::X86_INS_STOSB |
                capstone::x86_insn::X86_INS_STOSW |
                capstone::x86_insn::X86_INS_STOSD |
                capstone::x86_insn::X86_INS_STOSQ |
                capstone::x86_insn::X86_INS_MOVSB |
                capstone::x86_insn::X86_INS_MOVSW |
                capstone::x86_insn::X86_INS_MOVSD |
                capstone::x86_insn::X86_INS_MOVSQ => {
                    // loop -> head
                    control_flow_graph.unconditional_edge(loop_index,
                                                          head_index)?;
                },
                _ => bail!("unsupported instruction for rep prefix, 0x{:x}",
                           self.instruction().address)
            }
        }

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(terminating_index)?;

        Ok(())
    }


    /// Wraps the given instruction graph with the rep prefix inplace
    pub fn repne_prefix(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        if    control_flow_graph.entry().is_none()
           || control_flow_graph.exit().is_none() {
            bail!("control_flow_graph entry/exit was none");
        }

        let cx = self.get_register(x86_reg::X86_REG_ECX)?.get_full()?;

        let head_index = control_flow_graph.new_block()?.index();

        let loop_index = {
            let mut loop_block = control_flow_graph.new_block()?;
            cx.set(&mut loop_block,
                   Expr::sub(cx.get()?, expr_const(1, self.mode().bits()))?)?;
            loop_block.index()
        };

        let terminating_index = control_flow_graph.new_block()?.index();

        let entry = control_flow_graph.entry().clone().unwrap();
        let exit = control_flow_graph.exit().clone().unwrap();

        // head -> entry
        // head -> terminating
        control_flow_graph.conditional_edge(
            head_index,
            entry,
            Expr::cmpneq(cx.get()?, expr_const(0, self.mode().bits()))?
        )?;
        control_flow_graph.conditional_edge(
            head_index,
            terminating_index,
            Expr::cmpeq(cx.get()?, expr_const(0, self.mode().bits()))?
        )?;

        // exit -> loop
        control_flow_graph.unconditional_edge(exit, loop_index)?;

        if let capstone::InstrIdArch::X86(instruction_id) = self.instruction().id {
            match instruction_id {
                capstone::x86_insn::X86_INS_CMPSB |
                capstone::x86_insn::X86_INS_CMPSW |
                capstone::x86_insn::X86_INS_CMPSD |
                capstone::x86_insn::X86_INS_CMPSQ |
                capstone::x86_insn::X86_INS_SCASB |
                capstone::x86_insn::X86_INS_SCASW |
                capstone::x86_insn::X86_INS_SCASD |
                capstone::x86_insn::X86_INS_SCASQ => {
                    // loop -> head
                    control_flow_graph.conditional_edge(
                        loop_index,
                        head_index,
                        Expr::cmpeq(expr_scalar("ZF", 1), expr_const(0, 1))?
                    )?;
                    // loop -> terminating
                    control_flow_graph.conditional_edge(
                        loop_index,
                        terminating_index,
                        Expr::cmpeq(expr_scalar("ZF", 1), expr_const(1, 1))?
                    )?;
                },
                capstone::x86_insn::X86_INS_STOSB |
                capstone::x86_insn::X86_INS_STOSW |
                capstone::x86_insn::X86_INS_STOSD |
                capstone::x86_insn::X86_INS_STOSQ |
                capstone::x86_insn::X86_INS_MOVSB |
                capstone::x86_insn::X86_INS_MOVSW |
                capstone::x86_insn::X86_INS_MOVSD |
                capstone::x86_insn::X86_INS_MOVSQ => {
                    // loop -> head
                    control_flow_graph.unconditional_edge(loop_index,
                                                          head_index)?;
                },
                _ => bail!("unsupported instruction for rep prefix, \
                            instruction: {} {}, address: 0x{:x}",
                           self.instruction().mnemonic,
                           self.instruction().op_str,
                           self.instruction().address)
            }
        }

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(terminating_index)?;

        Ok(())
    }



    pub fn adc(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let result = block.temp(lhs.bits());

            // perform addition
            let addition = Expr::add(lhs.clone(), rhs.clone())?;
            let zext_cf = Expr::zext(lhs.bits(), expr_scalar("CF", 1))?;
            block.assign(result.clone(), Expr::add(addition, zext_cf)?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            self.set_of(&mut block,
                        result.clone().into(),
                        lhs.clone(),
                        rhs.clone())?;
            self.set_cf(&mut block, result.clone().into(), lhs.clone())?;

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn add(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let result = block.temp(lhs.bits());

            // perform addition
            block.assign(result.clone(), Expr::add(lhs.clone(), rhs.clone())?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            self.set_of(&mut block,
                        result.clone().into(),
                        lhs.clone(),
                        rhs.clone())?;
            self.set_cf(&mut block, result.clone().into(), lhs.clone())?;

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn and(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if rhs.bits() != lhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs)?;
            }

            let result = block.temp(lhs.bits());

            // perform addition
            block.assign(result.clone(), Expr::and(lhs.clone(), rhs.clone())?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            block.assign(scalar("CF", 1), expr_const(0, 1));
            block.assign(scalar("OF", 1), expr_const(0, 1));

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    /*
        BSF scans the bits in the second word or doubleword operand starting with
        bit 0. The ZF flag is cleared if the bits are all 0; otherwise, the ZF flag
        is set and the destination register is loaded with the bit index of the
        first set bit.
    */
    pub fn bsf(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        // create our head block
        let (head_index, rhs, counter) = {
            let (head_index, rhs) = {
                let mut head_block = control_flow_graph.new_block()?;

                // get started
                let rhs = self.operand_load(&mut head_block,
                                            &detail.operands[1])?;

                (head_block.index(), rhs)
            };

            let counter = {
                control_flow_graph.temp(rhs.bits())
            };

            let head_block = control_flow_graph.block_mut(head_index)?;

            // This is the loop preamble, and we'll always execute it
            head_block.assign(scalar("ZF", 1), expr_const(0, 1));
            head_block.assign(counter.clone(), expr_const(0, rhs.bits()));

            (head_index, rhs, counter)
        };

        // if rhs == 0 then ZF = 1 and we are done.
        let zero_index = {
            let zero_block = control_flow_graph.new_block()?;
            zero_block.assign(scalar("ZF", 1), expr_const(1, 1));

            zero_block.index()
        };

        // The loop body checks if the bits for our counter is set.
        let (bitfield, loop_index) = {
            let bitfield = control_flow_graph.temp(rhs.bits());

            let loop_block = control_flow_graph.new_block()?;
            loop_block.assign(bitfield.clone(),
                Expr::and(
                    Expr::shr(rhs.clone(), counter.clone().into())?,
                    expr_const(1, rhs.bits())
                )?
            );

            (bitfield, loop_block.index())
        };

        // While our bitfield == 0, we increment counter and keep looping
        let iterate_index = {
            let iterate_block = control_flow_graph.new_block()?;

            iterate_block.assign(
                counter.clone(),
                Expr::add(counter.clone().into(),
                          expr_const(1, counter.bits()))?
            );

            iterate_block.index()
        };

        // In our terminating block, we set the result to counter
        let terminating_index = {
            let mut terminating_block = control_flow_graph.new_block()?;

            self.operand_store(&mut terminating_block,
                               &detail.operands[0],
                               counter.into())?;

            terminating_block.index()
        };

        control_flow_graph.conditional_edge(
            head_index,
            zero_index,
            Expr::cmpeq(rhs.clone(), expr_const(0, rhs.bits()))?
        )?;
        control_flow_graph.conditional_edge(
            head_index,
            loop_index,
            Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?
        )?;

        control_flow_graph.unconditional_edge(zero_index, terminating_index)?;

        control_flow_graph.conditional_edge(
            loop_index,
            iterate_index,
            Expr::cmpeq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
        )?;
        control_flow_graph.conditional_edge(
            loop_index,
            terminating_index,
            Expr::cmpneq(bitfield.clone().into(), expr_const(0, bitfield.bits()))?
        )?;
        control_flow_graph.unconditional_edge(iterate_index, loop_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(terminating_index)?;

        Ok(())
    }


    /*
        BSR scans the bits in the second word or doubleword operand from the most
        significant bit to the least significant bit. The ZF flag is cleared if the
        bits are all 0; otherwise, ZF is set and the destination register is loaded
        with the bit index of the first set bit found when scanning in the reverse
        direction.
    */
    pub fn bsr(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let (head_index, rhs, counter) = {
            let (head_index, rhs) = {
                let mut head_block = control_flow_graph.new_block()?;

                // get started
                let rhs = self.operand_load(&mut head_block,
                                            &detail.operands[1])?;

                (head_block.index(), rhs)
            };

            let counter = {
                control_flow_graph.temp(rhs.bits())
            };

            let head_block = control_flow_graph.block_mut(head_index)?;

            // This is the loop preamble, and we'll always execute it
            head_block.assign(scalar("ZF", 1), expr_const(0, 1));
            head_block.assign(counter.clone(),
                              expr_const((rhs.bits() - 1) as u64,
                              rhs.bits()));

            (head_index, rhs, counter)
        };


        // if rhs == 0 then ZF = 1 and we are done.
        let zero_index = {
            let zero_block = control_flow_graph.new_block()?;
            zero_block.assign(scalar("ZF", 1), expr_const(1, 1));

            zero_block.index()
        };

        // The loop body checks if the bits for our counter is set
        let (bitfield, loop_index) = {
            let bitfield = control_flow_graph.temp(rhs.bits());

            let loop_block = control_flow_graph.new_block()?;
            loop_block.assign(bitfield.clone(),
                Expr::and(
                    Expr::shr(rhs.clone(), counter.clone().into())?,
                    expr_const(1, rhs.bits())
                )?
            );

            (bitfield, loop_block.index())
        };

        // While our bitfield == 0, we decrement counter and keep looping
        let iterate_index = {
            let iterate_block = control_flow_graph.new_block()?;

            iterate_block.assign(
                counter.clone(),
                Expr::sub(counter.clone().into(),
                          expr_const(1, counter.bits()))?
            );

            iterate_block.index()
        };

        // In our terminating block, we set the result to counter
        let terminating_index = {
            let mut terminating_block = control_flow_graph.new_block()?;

            self.operand_store(&mut terminating_block,
                               &detail.operands[0],
                               counter.into())?;

            terminating_block.index()
        };

        control_flow_graph.conditional_edge(
            head_index,
            zero_index,
            Expr::cmpeq(rhs.clone(), expr_const(0, rhs.bits()))?
        )?;
        control_flow_graph.conditional_edge(
            head_index,
            loop_index,
            Expr::cmpneq(rhs.clone(), expr_const(0, rhs.bits()))?
        )?;

        control_flow_graph.unconditional_edge(zero_index, terminating_index)?;

        control_flow_graph.conditional_edge(
            loop_index,
            iterate_index,
            Expr::cmpeq(bitfield.clone().into(),
                        expr_const(0, bitfield.bits()))?
        )?;
        control_flow_graph.conditional_edge(
            loop_index,
            terminating_index,
            Expr::cmpneq(bitfield.clone().into(),
                         expr_const(0, bitfield.bits()))?
        )?;
        control_flow_graph.unconditional_edge(iterate_index, loop_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(terminating_index)?;

        Ok(())
    }


    /*
        BT saves the value of the bit indicated by the base (first operand) and the
        bit offset (second operand) into the carry flag.

        CF ← BIT[LeftSRC, RightSRC];

        0F A3 BT r/m16,r16 3/12 Save bit in carry flag
        0F A3 BT r/m32,r32 3/12 Save bit in carry flag
        0F BA /4 ib BT r/m16,imm8 3/6 Save bit in carry flag
        0F BA /4 ib BT r/m32,imm8 3/6 Save bit in carry flag
    */
    pub fn bt(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        // create our head block
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get started
            let base = self.operand_load(&mut block, &detail.operands[0])?;
            let mut offset = self.operand_load(&mut block, &detail.operands[1])?;

            // let's ensure we have equal sorts
            if offset.bits() != base.bits() {
                let temp = block.temp(base.bits());
                block.assign(temp.clone(),
                             Expr::zext(base.bits(), offset.clone().into())?);
                offset = temp.into();
            }

            let temp = block.temp(base.bits());
            block.assign(temp.clone(), Expr::shr(base.into(), offset.into())?);
            block.assign(scalar("CF", 1), Expr::trun(1, temp.into())?);

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    /*
        BTC saves the value of the bit indicated by the base (first operand) and the
        bit offset (second operand) into the carry flag and then complements the
        bit.

        CF ← BIT[LeftSRC, RightSRC];
        BIT[LeftSRC, RightSRC] ← NOT BIT[LeftSRC, RightSRC];

        0F BB BTC r/m16,r16 6/13 Save bit in carry flag and complement
        0F BB BTC r/m32,r32 6/13 Save bit in carry flag and complement
        0F BA /7 ib BTC r/m16,imm8 6/8 Save bit in carry flag and complement
        0F BA /7 ib BTC r/m32,imm8 6/8 Save bit in carry flag and complement
    */
    pub fn btc(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        // create our head block
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get started
            let base = self.operand_load(&mut block, &detail.operands[0])?;
            let mut offset =
                self.operand_load(&mut block, &detail.operands[1])?;

            // let's ensure we have equal sorts
            if offset.bits() != base.bits() {
                let temp = block.temp(base.bits());
                block.assign(temp.clone(),
                             Expr::zext(base.bits(), offset.clone().into())?);
                offset = temp.into();
            }

            // this handles the assign to CF
            let temp = block.temp(base.bits());
            block.assign(temp.clone(),
                         Expr::shr(base.into(), offset.clone().into())?);
            block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

            let expr = Expr::xor(temp.clone().into(),
                                 expr_const(1, temp.clone().bits()))?;
            let expr = Expr::shl(expr, offset.into())?;
            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    /*
        BTR saves the value of the bit indicated by the base (first operand) and the
        bit offset (second operand) into the carry flag and then stores 0 in the
        bit.

        CF ← BIT[LeftSRC, RightSRC];
        BIT[LeftSRC, RightSRC] ← 0;

        0F B3 BTR r/m16,r16 6/13 Save bit in carry flag and reset
        0F B3 BTR r/m32,r32 6/13 Save bit in carry flag and reset
        0F BA /6 ib BTR r/m16,imm8 6/8 Save bit in carry flag and reset
        0F BA /6 ib BTR r/m32,imm8 6/8 Save bit in carry flag and reset
    */
    pub fn btr(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        // create our head block
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get started
            let base = self.operand_load(&mut block, &detail.operands[0])?;
            let mut offset = self.operand_load(&mut block, &detail.operands[1])?;

            // let's ensure we have equal sorts
            if offset.bits() != base.bits() {
                let temp = block.temp(base.bits());
                block.assign(temp.clone(),
                             Expr::zext(base.bits(), offset.clone().into())?);
                offset = temp.into();
            }

            // this handles the assign to CF
            let temp = block.temp(base.bits());
            block.assign(temp.clone(),
                         Expr::shr(base.clone().into(),
                                   offset.clone().into())?);
            block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

            let expr = Expr::shl(expr_const(1, base.bits()), offset.into())?;
            let expr = Expr::xor(
                expr,
                expr_const(0xffff_ffff_ffff_ffff, base.bits())
            )?;
            let expr = Expr::and(base.into(), expr)?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    /*
        BTS saves the value of the bit indicated by the base (first operand) and the
        bit offset (second operand) into the carry flag and then stores 1 in the
        bit.

        CF ← BIT[LeftSRC, RightSRC];
        BIT[LeftSRC, RightSRC] ← 1;

        0F AB BTS r/m16,r16 6/13 Save bit in carry flag and set
        0F AB BTS r/m32,r32 6/13 Save bit in carry flag and set
        0F BA /5 ib BTS r/m16,imm8 6/8 Save bit in carry flag and set
        0F BA /5 ib BTS r/m32,imm8 6/8 Save bit in carry flag and set
    */
    pub fn bts(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        // create our head block
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get started
            let base = self.operand_load(&mut block, &detail.operands[0])?;
            let mut offset =
                self.operand_load(&mut block, &detail.operands[1])?;

            // let's ensure we have equal sorts
            if offset.bits() != base.bits() {
                let temp = block.temp(base.bits());
                block.assign(temp.clone(),
                             Expr::zext(base.bits(), offset.clone().into())?);
                offset = temp.into();
            }

            // this handles the assign to CF
            let temp = block.temp(base.bits());
            block.assign(temp.clone(),
                         Expr::shr(base.clone().into(),
                                   offset.clone().into())?);
            block.assign(scalar("CF", 1), Expr::trun(1, temp.clone().into())?);

            let expr = Expr::shl(expr_const(1, base.bits()), offset.into())?;
            let expr = Expr::or(base.into(), expr)?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn bswap(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let src = self.operand_load(&mut block, &detail.operands[0])?;

            let expr = match self.mode {
                Mode::X86 => 
                    Expr::or(
                        Expr::or(
                            Expr::and(
                                Expr::shl(src.clone(), expr_const(24, 32))?,
                                expr_const(0xff00_0000, 32)
                            )?,
                            Expr::and(
                                Expr::shl(src.clone(), expr_const(8, 32))?,
                                expr_const(0x00ff_0000, 32)
                            )?
                        )?,
                        Expr::or(
                            Expr::and(
                                Expr::shr(src.clone(), expr_const(8, 32))?,
                                expr_const(0x0000_ff00, 32)
                            )?,
                            Expr::and(
                                Expr::shr(src, expr_const(24, 32))?,
                                expr_const(0x0000_00ff, 32)
                            )?
                        )?
                    )?,
                Mode::Amd64 =>
                    Expr::or(
                        Expr::or(
                            Expr::or(
                                Expr::and(
                                    Expr::shl(src.clone(), expr_const(56, 64))?,
                                    expr_const(0xff00_0000_0000_0000, 64)
                                )?,
                                Expr::and(
                                    Expr::shl(src.clone(), expr_const(40, 64))?,
                                    expr_const(0x00ff_0000_0000_0000, 64)
                                )?
                            )?,
                            Expr::or(
                                Expr::and(
                                    Expr::shl(src.clone(), expr_const(24, 64))?,
                                    expr_const(0x0000_ff00_0000_0000, 64)
                                )?,
                                Expr::and(
                                    Expr::shl(src.clone(), expr_const(8, 64))?,
                                    expr_const(0x0000_00ff_0000_0000, 64)
                                )?
                            )?
                        )?,
                        Expr::or(
                            Expr::or(
                                Expr::and(
                                    Expr::shr(src.clone(), expr_const(8, 64))?,
                                    expr_const(0x0000_0000_ff00_0000, 64)
                                )?,
                                Expr::and(
                                    Expr::shr(src.clone(), expr_const(24, 64))?,
                                    expr_const(0x0000_0000_00ff_0000, 64)
                                )?,
                            )?,
                            Expr::or(
                                Expr::and(
                                    Expr::shr(src.clone(), expr_const(40, 64))?,
                                    expr_const(0x0000_0000_0000_ff00, 64)
                                )?,
                                Expr::and(
                                    Expr::shr(src.clone(), expr_const(56, 64))?,
                                    expr_const(0x0000_0000_0000_00ff, 64)
                                )?
                            )?
                        )?
                    )?
            };

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn call(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get started
            let dst = self.operand_load(&mut block, &detail.operands[0])?;

            let ret_addr =
                self.instruction().address + self.instruction().size as u64;

            self.mode().push_value(&mut block,
                                   expr_const(ret_addr, self.mode().bits()))?;

            block.branch(dst);

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn cbw(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let al = self.get_register(x86_reg::X86_REG_AL)?;
            let ax = self.get_register(x86_reg::X86_REG_AX)?;

            ax.set(&mut block, Expr::sext(16, al.get()?)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn cdq(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let eax = self.get_register(x86_reg::X86_REG_EAX)?;
            let edx = self.get_register(x86_reg::X86_REG_EDX)?;

            // isolate the sign bits of ax
            let expr = Expr::shr(eax.get()?, expr_const(31, 32))?;
            let expr = Expr::trun(1, expr)?;
            let expr = Expr::sext(32, expr)?;

            edx.set(&mut block, expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn cdqe(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let eax = self.get_register(x86_reg::X86_REG_EAX)?;
            let rax = self.get_register(x86_reg::X86_REG_RAX)?;

            rax.set(&mut block, Expr::sext(64, eax.get()?)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn clc(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let block_index = {
            let block = control_flow_graph.new_block()?;

            block.assign(scalar("CF", 1), expr_const(0, 1));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn cld(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let block_index = {
            let block = control_flow_graph.new_block()?;

            block.assign(scalar("DF", 1), expr_const(0, 1));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn cli(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let block_index = {
            let block = control_flow_graph.new_block()?;

            block.assign(scalar("IF", 1), expr_const(0, 1));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn cmc(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let block_index = {
            let block = control_flow_graph.new_block()?;

            let expr = Expr::xor(expr_scalar("CF", 1), expr_const(1, 1))?;
            block.assign(scalar("CF", 1), expr);

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn cmovcc(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let head_index = {
            let block = control_flow_graph.new_block()?;

            // This nop allows us to find this instruction in traces, even when
            // then false branch is taken and no instruction is executed.
            block.nop();

            block.index()
        };

        let tail_index = {
            let block = control_flow_graph.new_block()?;

            block.index()
        };

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let src = self.operand_load(&mut block, &detail.operands[1])?;

            self.operand_store(&mut block, &detail.operands[0], src)?;

            block.index()
        };

        let condition = self.cc_condition()?;

        control_flow_graph.conditional_edge(head_index,
                                            block_index,
                                            condition.clone())?;
        control_flow_graph.conditional_edge(
            head_index,
            tail_index,
            Expr::cmpeq(condition, expr_const(0, 1))?
        )?;
        control_flow_graph.unconditional_edge(block_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }



    pub fn cmp(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if rhs.bits() != lhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs.into())?;
            }

            let expr = Expr::sub(lhs.clone(), rhs.clone())?;

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
            self.set_cf(&mut block, expr.clone(), lhs.clone())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn cmpsb(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let si = match *self.mode() {
            Mode::X86 => self.get_register(x86_reg::X86_REG_ESI)?,
            Mode::Amd64 => self.get_register(x86_reg::X86_REG_RSI)?
        };
        let di = match *self.mode() {
            Mode::X86 => self.get_register(x86_reg::X86_REG_EDI)?,
            Mode::Amd64 => self.get_register(x86_reg::X86_REG_RDI)?
        };
        let bits = self.mode().bits();

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if rhs.bits() != lhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs.into())?;
            }

            let expr = Expr::sub(lhs.clone(), rhs.clone())?;

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
            self.set_cf(&mut block, expr.clone(), lhs.clone())?;

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::add(si.get()?, expr_const(1, bits))?)?;
            di.set(&mut block, Expr::add(di.get()?, expr_const(1, bits))?)?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::sub(si.get()?, expr_const(1, bits))?)?;
            di.set(&mut block, Expr::sub(di.get()?, expr_const(1, bits))?)?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };


        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }



    pub fn cmpxchg(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let (head_index, dest, lhs, rhs) = {
            let mut block = control_flow_graph.new_block()?;

            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let dest = match rhs.bits() {
                8 => self.get_register(x86_reg::X86_REG_AL)?,
                16 => self.get_register(x86_reg::X86_REG_AX)?,
                32 => self.get_register(x86_reg::X86_REG_EAX)?,
                64 => self.get_register(x86_reg::X86_REG_RAX)?,
                _ => bail!("can't figure out dest for xmpxchg, rhs.bits()={}", rhs.bits())
            };

            (block.index(), dest, lhs, rhs)
        };

        let taken_index = {
            let mut block = control_flow_graph.new_block()?;

            block.assign(scalar("ZF", 1), expr_const(1, 1));
            self.operand_store(&mut block, &detail.operands[0], rhs.clone())?;

            block.index()
        };

        let not_taken_index = {
            let mut block = control_flow_graph.new_block()?;

            block.assign(scalar("ZF", 1), expr_const(0, 1));
            dest.set(&mut block, lhs.clone())?;

            block.index()
        };

        let tail_index = {
            let mut block = control_flow_graph.new_block()?;

            let result = Expr::sub(lhs.clone(), rhs.clone())?;
            self.set_sf(&mut block, result.clone())?;
            self.set_of(&mut block, result.clone(), lhs.clone(), rhs.clone())?;
            self.set_cf(&mut block, result.clone(), lhs.clone())?;

            block.index()
        };

        let condition = Expr::cmpeq(dest.get()?, lhs.clone())?;

        control_flow_graph.conditional_edge(head_index,
                                            taken_index,
                                            condition.clone())?;
        control_flow_graph.conditional_edge(
            head_index,
            not_taken_index,
            Expr::cmpeq(condition.clone(), expr_const(0, 1))?
        )?;
        control_flow_graph.unconditional_edge(taken_index, tail_index)?;
        control_flow_graph.unconditional_edge(not_taken_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }


    pub fn cwd(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let ax = self.get_register(x86_reg::X86_REG_AX)?;
        let dx = self.get_register(x86_reg::X86_REG_DX)?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // isolate the sign bits of ax
            let expr = Expr::shr(ax.get()?, expr_const(15, 16))?;
            let expr = Expr::trun(1, expr)?;
            let expr = Expr::sext(16, expr)?;

            dx.set(&mut block, expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn cwde(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let ax = self.get_register(x86_reg::X86_REG_AX)?;
        let eax = self.get_register(x86_reg::X86_REG_EAX)?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            eax.set(&mut block, Expr::sext(32, ax.get()?)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn dec(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.operand_load(&mut block, &detail.operands[0])?;

            let expr = Expr::sub(dst.clone().into(), expr_const(1, dst.bits()))?;

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block,
                        expr.clone(),
                        dst.clone(),
                        expr_const(1, dst.bits()))?;
            self.set_cf(&mut block, expr.clone(), dst.clone())?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn div(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let divisor = self.operand_load(&mut block, &detail.operands[0])?;
            let divisor = Expr::zext(divisor.bits() * 2, divisor)?;

            let dividend: Expr = match divisor.bits() {
                16 => self.get_register(x86_reg::X86_REG_AX)?.get()?,
                32 => {
                    let expr_dx =
                        Expr::zext(
                            32,
                            self.get_register(x86_reg::X86_REG_DX)?.get()?
                        )?;
                    let expr_dx =
                        Expr::shl(expr_dx, expr_const(16, 32))?;
                    Expr::or(
                        expr_dx,
                        Expr::zext(
                            32,
                            self.get_register(x86_reg::X86_REG_AX)?.get()?
                        )?
                    )?
                },
                64 => {
                    let expr_edx =
                        Expr::zext(
                            64,
                            self.get_register(x86_reg::X86_REG_EDX)?.get()?
                        )?;
                    let expr_edx =
                        Expr::shl(expr_edx, expr_const(32, 64))?;
                    Expr::or(
                        expr_edx,
                        Expr::zext(
                            64,
                            self.get_register(x86_reg::X86_REG_EAX)?.get()?
                        )?
                    )?
                },
                128 => {
                    let expr_edx =
                        Expr::zext(
                            128,
                            self.get_register(x86_reg::X86_REG_RDX)?.get()?
                        )?;
                    let expr_edx =
                        Expr::shl(expr_edx, expr_const(64, 128))?;
                    Expr::or(
                        expr_edx,
                        Expr::zext(
                            128,
                            self.get_register(x86_reg::X86_REG_EAX)?.get()?
                        )?
                    )?
                },
                _ => return Err("invalid bit-width in x86 div".into())
            };

            let quotient  = block.temp(divisor.bits());
            let remainder = block.temp(divisor.bits());

            block.assign(quotient.clone(), Expr::divu(dividend.clone(), divisor.clone())?);
            block.assign(remainder.clone(), Expr::modu(dividend, divisor.clone())?);

            match divisor.bits() {
                16 => {
                    let al = self.get_register(x86_reg::X86_REG_AL)?;
                    let ah = self.get_register(x86_reg::X86_REG_AH)?;
                    al.set(&mut block, Expr::trun(8, quotient.into())?)?;
                    ah.set(&mut block, Expr::trun(8, remainder.into())?)?;
                },
                32 => {
                    let ax = self.get_register(x86_reg::X86_REG_AX)?;
                    let dx = self.get_register(x86_reg::X86_REG_DX)?;
                    ax.set(&mut block, Expr::trun(16, quotient.into())?)?;
                    dx.set(&mut block, Expr::trun(16, remainder.into())?)?;
                },
                64 => {
                    let eax = self.get_register(x86_reg::X86_REG_EAX)?;
                    let edx = self.get_register(x86_reg::X86_REG_EDX)?;
                    eax.set(&mut block, Expr::trun(32, quotient.into())?)?;
                    edx.set(&mut block, Expr::trun(32, remainder.into())?)?;
                },
                128 => {
                    let rax = self.get_register(x86_reg::X86_REG_RAX)?;
                    let rdx = self.get_register(x86_reg::X86_REG_RDX)?;
                    rax.set(&mut block, Expr::trun(64, quotient.into())?)?;
                    rdx.set(&mut block, Expr::trun(64, remainder.into())?)?;
                },
                _ => return Err("invalid bit-width in x86 div".into())
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    // This is essentially the exact same as div with the signs of the arith ops
    // reversed.
    pub fn idiv(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let divisor = self.operand_load(&mut block, &detail.operands[0])?;
            let divisor = Expr::zext(divisor.bits() * 2, divisor)?;

            let dividend: Expr = match divisor.bits() {
                16 => self.get_register(x86_reg::X86_REG_AX)?.get()?,
                32 => {
                    let expr_dx =
                        Expr::zext(
                            32,
                            self.get_register(x86_reg::X86_REG_DX)?.get()?
                        )?;
                    let expr_dx =
                        Expr::shl(expr_dx, expr_const(16, 32))?;
                    Expr::or(
                        expr_dx,
                        Expr::zext(
                            32,
                            self.get_register(x86_reg::X86_REG_AX)?.get()?
                        )?
                    )?
                },
                64 => {
                    let expr_edx =
                        Expr::zext(
                            64,
                            self.get_register(x86_reg::X86_REG_EDX)?.get()?
                        )?;
                    let expr_edx =
                        Expr::shl(expr_edx, expr_const(32, 64))?;
                    Expr::or(
                        expr_edx,
                        Expr::zext(
                            64,
                            self.get_register(x86_reg::X86_REG_EAX)?.get()?
                        )?
                    )?
                },
                128 => {
                    let expr_edx =
                        Expr::zext(
                            128,
                            self.get_register(x86_reg::X86_REG_RDX)?.get()?
                        )?;
                    let expr_edx =
                        Expr::shl(expr_edx, expr_const(64, 128))?;
                    Expr::or(
                        expr_edx,
                        Expr::zext(
                            128,
                            self.get_register(x86_reg::X86_REG_EAX)?.get()?
                        )?
                    )?
                },
                _ => return Err("invalid bit-width in x86 div".into())
            };

            let quotient  = block.temp(divisor.bits());
            let remainder = block.temp(divisor.bits());

            block.assign(quotient.clone(), Expr::divs(dividend.clone(), divisor.clone())?);
            block.assign(remainder.clone(), Expr::mods(dividend, divisor.clone())?);

            match divisor.bits() {
                16 => {
                    let al = self.get_register(x86_reg::X86_REG_AL)?;
                    let ah = self.get_register(x86_reg::X86_REG_AH)?;
                    al.set(&mut block, Expr::trun(8, quotient.into())?)?;
                    ah.set(&mut block, Expr::trun(8, remainder.into())?)?;
                },
                32 => {
                    let ax = self.get_register(x86_reg::X86_REG_AX)?;
                    let dx = self.get_register(x86_reg::X86_REG_DX)?;
                    ax.set(&mut block, Expr::trun(16, quotient.into())?)?;
                    dx.set(&mut block, Expr::trun(16, remainder.into())?)?;
                },
                64 => {
                    let eax = self.get_register(x86_reg::X86_REG_EAX)?;
                    let edx = self.get_register(x86_reg::X86_REG_EDX)?;
                    eax.set(&mut block, Expr::trun(32, quotient.into())?)?;
                    edx.set(&mut block, Expr::trun(32, remainder.into())?)?;
                },
                128 => {
                    let rax = self.get_register(x86_reg::X86_REG_RAX)?;
                    let rdx = self.get_register(x86_reg::X86_REG_RDX)?;
                    rax.set(&mut block, Expr::trun(32, quotient.into())?)?;
                    rdx.set(&mut block, Expr::trun(32, remainder.into())?)?;
                },
                _ => return Err("invalid bit-width in x86 div".into())
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    // If we have one operand, we go in AX, DX:AX, EDX:EAX
    // If we have two operands, sign-extend rhs if required, go in 0 operand
    // If we have three operands, sign-extend rhs if required, go in 0 operand
    pub fn imul(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // Get multiplicand
            let multiplicand = match detail.op_count {
                1 => match detail.operands[0].size {
                    1 => self.get_register(x86_reg::X86_REG_AL)?.get()?,
                    2 => self.get_register(x86_reg::X86_REG_AX)?.get()?,
                    4 => self.get_register(x86_reg::X86_REG_EAX)?.get()?,
                    8 => self.get_register(x86_reg::X86_REG_RAX)?.get()?,
                    _ => bail!("invalid operand size for imul")
                },
                2 => self.operand_load(&mut block, &detail.operands[0])?,
                3 => self.operand_load(&mut block, &detail.operands[1])?,
                _ => bail!("invalid number of operands for imul {} at 0x{:x}",
                        detail.op_count,
                        self.instruction().address)
            };

            // Get multiplier
            let multiplier = match detail.op_count {
                1 => self.operand_load(&mut block, &detail.operands[0])?,
                2 => {
                    let multiplier =
                        self.operand_load(&mut block, &detail.operands[1])?;
                    if multiplier.bits() < multiplicand.bits() {
                        Expr::sext(multiplicand.bits(), multiplier)?
                    }
                    else {
                        multiplier
                    }
                },
                3 => {
                    let multiplier =
                        self.operand_load(&mut block, &detail.operands[2])?;
                    if multiplier.bits() < multiplicand.bits() {
                        Expr::sext(multiplicand.bits(), multiplier)?
                    }
                    else {
                        multiplier
                    }
                }
                _ => bail!("invalid number of operands for imul")
            };

            // Perform multiplication
            let bit_width = multiplicand.bits() * 2;

            let result = block.temp(bit_width);
            block.assign(result.clone(), Expr::mul(
                Expr::zext(bit_width, multiplicand)?,
                Expr::zext(bit_width, multiplier)?
            )?);

            // Set the result
            match detail.op_count {
                1 => {
                    match detail.operands[0].size {
                        1 => self.get_register(x86_reg::X86_REG_AX)?
                                .set(&mut block, result.clone().into())?,
                        2 => {
                            let dx = self.get_register(x86_reg::X86_REG_DX)?;
                            let ax = self.get_register(x86_reg::X86_REG_AX)?;
                            let expr = Expr::shr(result.clone().into(),
                                                 expr_const(16, 32))?;
                            dx.set(&mut block, Expr::trun(16, expr)?)?;
                            ax.set(&mut block,
                                   Expr::trun(16, result.clone().into())?)?;
                        },
                        4 => {
                            let edx = self.get_register(x86_reg::X86_REG_EDX)?;
                            let eax = self.get_register(x86_reg::X86_REG_EAX)?;
                            let expr = Expr::shr(result.clone().into(),
                                                 expr_const(32, 64))?;
                            edx.set(&mut block, Expr::trun(32, expr)?)?;
                            eax.set(&mut block,
                                    Expr::trun(32, result.clone().into())?)?;
                        },
                        8 => {
                            let rdx = self.get_register(x86_reg::X86_REG_RDX)?;
                            let rax = self.get_register(x86_reg::X86_REG_RAX)?;
                            let expr = Expr::shr(result.clone().into(),
                                                 expr_const(64, 128))?;
                            rdx.set(&mut block, Expr::trun(64, expr)?)?;
                            rax.set(&mut block,
                                    Expr::trun(64, result.clone().into())?)?;
                        },
                        _ => bail!("Invalid operand size for imul")
                    }
                },
                2 => {
                    let expr = Expr::trun(bit_width / 2, result.clone().into())?;
                    self.operand_store(&mut block, &detail.operands[0], expr)?;
                }
                3 => {
                    let expr = Expr::trun(bit_width / 2, result.clone().into())?;
                    self.operand_store(&mut block, &detail.operands[0], expr)?;
                }
                _ => bail!("invalid number of operands for imul")
            }


            // Set flags
            block.assign(scalar("OF", 1),
                Expr::cmpneq(
                    Expr::trun(
                        bit_width / 2,
                        Expr::shr(
                            result.clone().into(),
                            expr_const((bit_width / 2) as u64, bit_width)
                        )?
                    )?,
                    expr_const(0, bit_width / 2)
                )?
            );
            block.assign(scalar("CF", 1), expr_scalar("OF", 1));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn inc(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.operand_load(&mut block, &detail.operands[0])?;

            let expr = Expr::add(dst.clone().into(),
                                 expr_const(1, dst.bits()))?;

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block,
                        expr.clone(),
                        dst.clone(),
                        expr_const(1, dst.bits()))?;
            self.set_cf(&mut block, expr.clone(), dst.clone())?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn int(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let expr = self.operand_load(&mut block, &detail.operands[0])?;

            block.intrinsic(
                Intrinsic::new(
                    "int",
                    format!("int {}", expr),
                    vec![expr],
                    None,
                    None,
                    self.instruction().bytes.get(0..4).unwrap().to_vec()
                ));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn jmp(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // we only need to emit a brc here if the destination cannot be determined
            // at translation time
            if detail.operands[0].type_ != x86_op_type::X86_OP_IMM {
                let dst = self.operand_load(&mut block, &detail.operands[0])?;
                block.branch(dst);
            }
            else {
                block.nop();
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn lea(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.get_register(detail.operands[0].reg())?;
            let mut src =
                self.mode().operand_value(&detail.operands[1],
                                          self.instruction())?;

            if src.bits() > dst.bits() {
                src = Expr::trun(dst.bits(), src)?;
            }

            dst.set(&mut block, src)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn leave(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let sp = self.get_register(x86_reg::X86_REG_ESP)?.get_full()?;
            let bp = self.get_register(x86_reg::X86_REG_EBP)?.get_full()?;

            sp.set(&mut block, bp.get()?)?;
            let temp = self.mode().pop_value(&mut block, self.mode().bits())?;
            bp.set(&mut block, temp)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn lodsb(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let si = self.get_register(x86_reg::X86_REG_ESI)?.get_full()?;

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            self.get_register(x86_reg::X86_REG_AL)?.set(&mut block, rhs)?;

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::add(si.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::sub(si.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };


        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }


    pub fn lodsd(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let si = self.get_register(x86_reg::X86_REG_ESI)?.get_full()?;

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            self.get_register(x86_reg::X86_REG_EAX)?.set(&mut block, rhs)?;

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::add(si.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(&mut block, Expr::sub(si.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };


        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }


    pub fn loop_(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let cx = self.get_register(x86_reg::X86_REG_CX)?.get_full()?;
            cx.set(&mut block, Expr::sub(cx.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn mov(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let src = self.operand_load(&mut block, &detail.operands[1])?;

            self.operand_store(&mut block, &detail.operands[0], src)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn movq(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let mut src = self.operand_load(&mut block, &detail.operands[1])?;

            // When the src is an xmm register, the lower 64 bits are copied,
            // and the high bits are zeroed out.
            // We can start by ensuring all src operands are 64-bits.
            if src.bits() > 64 {
                src = Expr::trun(64, src)?;
            }

            // Valid destinations are 64-bit memory location, 64-bit register,
            // and 128-bit xmm register. We're already good for 64-bit cases,
            // just need to zext for 128-bit case.
            match detail.operands[0].type_ {
                x86_op_type::X86_OP_REG => {
                    // mov to 64-bit register
                    let register = self.get_register(detail.operands[0].reg())?;
                    if register.bits() == 128 {
                        src = Expr::zext(128, src)?;
                    }
                }
                _ => {}
            }

            self.operand_store(&mut block, &detail.operands[0], src)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn movs(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let bits_size = detail.operands[1].size as usize * 8;

        let si = self.get_register(x86_reg::X86_REG_SI)?.get_full()?;
        let di = self.get_register(x86_reg::X86_REG_DI)?.get_full()?;

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            let temp = block.temp(bits_size);
            block.load(temp.clone(), si.get()?);
            block.store(di.get()?, temp.into());

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(
                &mut block,
                Expr::add(
                    si.get()?,
                    expr_const((bits_size / 8) as u64, self.mode().bits())
                )?
            )?;

            di.set(
                &mut block,
                Expr::add(
                    di.get()?,
                    expr_const((bits_size / 8) as u64, self.mode().bits())
                )?
            )?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            si.set(
                &mut block,
                Expr::sub(
                    si.get()?,
                    expr_const((bits_size / 8) as u64, self.mode().bits())
                )?
            )?;

            di.set(
                &mut block,
                Expr::sub(
                    di.get()?,
                    expr_const((bits_size / 8) as u64, self.mode().bits())
                )?
            )?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };


        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;

        Ok(())
    }



    pub fn movsx(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let src = self.operand_load(&mut block, &detail.operands[1])?;
            let value = Expr::sext((detail.operands[0].size as usize) * 8, src)?;

            self.operand_store(&mut block, &detail.operands[0], value)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn movzx(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let src = self.operand_load(&mut block, &detail.operands[1])?;
            let value =
                Expr::zext((detail.operands[0].size as usize) * 8, src)?;

            self.operand_store(&mut block, &detail.operands[0], value)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn mul(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let rhs = self.operand_load(&mut block, &detail.operands[0])?;

            let lhs = match rhs.bits() {
                8 => self.get_register(x86_reg::X86_REG_AL)?.get()?,
                16 => self.get_register(x86_reg::X86_REG_AX)?.get()?,
                32 => self.get_register(x86_reg::X86_REG_EAX)?.get()?,
                64 => self.get_register(x86_reg::X86_REG_RAX)?.get()?,
                _ => bail!("invalid bit-width for mul")
            };

            let bit_width = rhs.bits() * 2;
            let result = block.temp(bit_width);
            let expr = Expr::mul(Expr::zext(bit_width, lhs)?,
                                 Expr::zext(bit_width, rhs.clone())?)?;
            block.assign(result.clone(), expr);

            match rhs.bits() {
                8 => {
                    let ax = self.get_register(x86_reg::X86_REG_AX)?;
                    ax.set(&mut block, result.into())?;
                    let expr =
                        Expr::cmpeq(self.get_register(x86_reg::X86_REG_AH)?
                                        .get()?,
                                    expr_const(0, 8))?;
                    block.assign(scalar("OF", 1), expr);
                    block.assign(scalar("CF", 1), expr_scalar("OF", 1));
                },
                16 => {
                    let dx = self.get_register(x86_reg::X86_REG_DX)?;
                    let ax = self.get_register(x86_reg::X86_REG_AX)?;
                    dx.set(&mut block,
                           Expr::trun(16, Expr::shr(result.clone().into(),
                                                    expr_const(16, 32))?)?)?;
                    ax.set(&mut block, Expr::trun(16, result.into())?)?;
                    block.assign(scalar("OF", 1),
                                 Expr::cmpeq(dx.get()?, expr_const(0, 16))?);
                    block.assign(scalar("CF", 1), expr_scalar("OF", 1));
                },
                32 => {
                    let edx = self.get_register(x86_reg::X86_REG_EDX)?;
                    let eax = self.get_register(x86_reg::X86_REG_EAX)?;
                    edx.set(&mut block,
                            Expr::trun(32, Expr::shr(result.clone().into(),
                                                     expr_const(32, 64))?)?)?;
                    eax.set(&mut block, Expr::trun(32, result.into())?)?;
                    block.assign(scalar("OF", 1),
                                 Expr::cmpeq(edx.get()?, expr_const(0, 32))?);
                    block.assign(scalar("CF", 1), expr_scalar("OF", 1));
                },
                64 => {
                    let rdx = self.get_register(x86_reg::X86_REG_RDX)?;
                    let rax = self.get_register(x86_reg::X86_REG_RAX)?;
                    rdx.set(&mut block,
                            Expr::trun(64, Expr::shr(result.clone().into(),
                                                     expr_const(64, 128))?)?)?;
                    rax.set(&mut block, Expr::trun(64, result.into())?)?;
                    block.assign(scalar("OF", 1),
                                 Expr::cmpeq(rdx.get()?, expr_const(0, 64))?);
                    block.assign(scalar("CF", 1), expr_scalar("OF", 1));
                }
                _ => bail!("invalid bit-width for mul")
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn neg(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.operand_load(&mut block, &detail.operands[0])?;

            let result = block.temp(dst.bits());

            block.assign(scalar("CF", 1),
                         Expr::cmpneq(dst.clone().into(),
                                      expr_const(0, dst.bits()))?);

            block.assign(result.clone(), Expr::sub(expr_const(0, dst.bits()),
                                                   dst.clone().into())?);

            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            self.set_of(&mut block,
                        result.clone().into(),
                        expr_const(0, dst.bits()),
                        dst.clone().into())?;

            self.operand_store(&mut block,
                               &detail.operands[0],
                               result.clone().into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn nop(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            block.nop();

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn not(&self, control_flow_graph: &mut ControlFlowGraph,) -> Result<()> {
        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let dst = self.operand_load(&mut block, &detail.operands[0])?;

            let expr = Expr::xor(dst.clone(), expr_const(!0, dst.bits()))?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn or(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let result = block.temp(lhs.bits());

            if lhs.bits() != rhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs)?;
            }

            // perform addition
            block.assign(result.clone(), Expr::or(lhs.clone(), rhs.clone())?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            block.assign(scalar("CF", 1), expr_const(0, 1));
            block.assign(scalar("OF", 1), expr_const(0, 1));

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn paddq(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() == 64 {
                self.operand_store(
                    &mut block,
                    &detail.operands[0],
                    Expr::add(lhs, rhs)?)?;
            }
            else if lhs.bits() == 128 {
                let upper =
                    Expr::shl(expr_const(64, 128),
                        Expr::add(
                            Expr::shr(expr_const(64, 128), lhs.clone())?,
                            Expr::shr(expr_const(64, 128), lhs.clone())?)?)?;
                let lower =
                    Expr::and(
                        expr_const(0xffff_ffff_ffff_ffff, 128),
                        Expr::add(lhs, rhs)?)?;
                self.operand_store(
                    &mut block,
                    &detail.operands[0],
                    Expr::or(upper, lower)?)?;
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pcmpeqb(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let temp = block.temp(lhs.bits());

            block.assign(temp.clone(),
                Expr::ite(
                    Expr::cmpeq(
                        Expr::trun(8, lhs.clone())?,
                        Expr::trun(8, rhs.clone())?)?,
                    expr_const(0xff, lhs.bits()),
                    expr_const(0, lhs.bits()))?);

            for i in 1..(lhs.bits() / 8) {
                let shift_constant = expr_const((i * 8) as u64, lhs.bits());
                let cmp_lhs =
                    Expr::trun(8,
                        Expr::shr(lhs.clone(), shift_constant.clone())?)?;
                let cmp_rhs =
                    Expr::trun(8,
                        Expr::shr(rhs.clone(), shift_constant.clone())?)?;

                block.assign(temp.clone(),
                    Expr::or(
                        temp.clone().into(),
                        Expr::shl(
                            Expr::ite(
                                Expr::cmpeq(cmp_lhs, cmp_rhs)?,
                                Expr::zext(lhs.bits(), expr_const(0xff, 8))?,
                                Expr::zext(lhs.bits(), expr_const(0, 8))?
                            )?,
                            shift_constant
                        )?
                    )?
                );
            }

            self.operand_store(&mut block, &detail.operands[0], temp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pcmpeqd(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let temp = block.temp(lhs.bits());

            block.assign(temp.clone(),
                Expr::ite(
                    Expr::cmpeq(
                        Expr::trun(32, lhs.clone())?,
                        Expr::trun(32, rhs.clone())?)?,
                    expr_const(0xffff_ffff, lhs.bits()),
                    expr_const(0, lhs.bits()))?);

            for i in 1..(lhs.bits() / 32) {
                let shift_constant = expr_const((i * 32) as u64, lhs.bits());
                let cmp_lhs =
                    Expr::trun(32, 
                        Expr::shr(lhs.clone(), shift_constant.clone())?)?;
                let cmp_rhs =
                    Expr::trun(32,
                        Expr::shr(rhs.clone(), shift_constant.clone())?)?;

                block.assign(temp.clone(),
                    Expr::or(
                        temp.clone().into(),
                        Expr::shl(
                            Expr::ite(
                                Expr::cmpeq(cmp_lhs, cmp_rhs)?,
                                Expr::zext(lhs.bits(), expr_const(0xffff_ffff, 32))?,
                                Expr::zext(lhs.bits(), expr_const(0, 32))?
                            )?,
                            shift_constant
                        )?
                    )?
                );
            }

            self.operand_store(&mut block, &detail.operands[0], temp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pmovmskb(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.get_register(detail.operands[0].reg())?;
            let src = self.operand_load(&mut block, &detail.operands[1])?;

            let temp = block.temp(dst.bits());

            block.assign(temp.clone(),
                Expr::ite(
                    Expr::cmpeq(
                        Expr::trun(1, Expr::shr(src.clone(), expr_const(7, src.bits()))?)?,
                        expr_const(1, 1))?,
                    expr_const(1, dst.bits()),
                    expr_const(0, dst.bits()))?);

            for i in 1..(src.bits() / 8) {
                let cmp =
                    Expr::cmpeq(
                        Expr::trun(1,
                            Expr::shr(src.clone(),
                                      expr_const(((i as u64 + 1) * 8) - 1, src.bits()))?)?,
                        expr_const(1, 1))?;
                let bit = Expr::ite(
                    cmp,
                    expr_const(1 << i, dst.bits()),
                    expr_const(0, dst.bits()))?;

                block.assign(temp.clone(), Expr::or(temp.clone().into(), bit)?);
            }

            self.operand_store(&mut block, &detail.operands[0], temp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pminub(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let temp = block.temp(lhs.bits());

            block.assign(temp.clone(),
                Expr::ite(
                    Expr::cmpltu(
                        Expr::trun(8, lhs.clone())?,
                        Expr::trun(8, rhs.clone())?)?,
                    Expr::and(lhs.clone(), expr_const(0xff, lhs.bits()))?,
                    Expr::and(rhs.clone(), expr_const(0xff, rhs.bits()))?)?);

            for i in 1..(lhs.bits() / 8) {
                let mask =
                    const_(0xff, lhs.bits())
                        .shl(&const_(8 * i as u64, lhs.bits()))?;

                let l8 = Expr::and(lhs.clone(), mask.clone().into())?;
                let r8 = Expr::and(rhs.clone(), mask.into())?;

                let ite =
                    Expr::ite(
                        Expr::cmpltu(l8.clone(), r8.clone())?,
                        l8,
                        r8)?;

                block.assign(temp.clone(), Expr::or(temp.clone().into(), ite)?);
            }

            self.operand_store(&mut block, &detail.operands[0], temp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn psubq(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() == 64 {
                self.operand_store(
                    &mut block,
                    &detail.operands[0],
                    Expr::sub(lhs, rhs)?)?;
            }
            else if lhs.bits() == 128 {
                let upper =
                    Expr::shl(expr_const(64, 128),
                        Expr::sub(
                            Expr::shr(expr_const(64, 128), lhs.clone())?,
                            Expr::shr(expr_const(64, 128), lhs.clone())?)?)?;
                let lower =
                    Expr::sub(
                        expr_const(0xffff_ffff_ffff_ffff, 128),
                        Expr::sub(lhs, rhs)?)?;
                self.operand_store(
                    &mut block,
                    &detail.operands[0],
                    Expr::or(upper, lower)?)?;
            }

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pop(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let value = match detail.operands[0].type_ {
                x86_op_type::X86_OP_MEM =>
                    self.mode()
                        .pop_value(&mut block,
                                   detail.operands[0].size as usize * 8)?,
                x86_op_type::X86_OP_REG => 
                    self.mode()
                        .pop_value(&mut block,
                                   self.get_register(detail.operands[0].reg())?
                                       .bits())?,
                _ => bail!("invalid op type for `pop` instruction")
            };

            self.operand_store(&mut block, &detail.operands[0], value)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn push(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let value = self.operand_load(&mut block, &detail.operands[0])?;

            self.mode().push_value(&mut block, value)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn pxor(&self, control_flow_graph: &mut ControlFlowGraph)
        -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            self.operand_store(
                &mut block,
                &detail.operands[0],
                Expr::xor(lhs, rhs)?
            )?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn ret(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let value = self.mode().pop_value(&mut block, self.mode().bits())?;

            if detail.op_count == 1 {
                let imm = self.operand_load(&mut block, &detail.operands[0])?;
                let sp = self.get_register(x86_reg::X86_REG_SP)?.get_full()?;
                sp.set(&mut block, Expr::add(sp.get()?, imm)?)?;
            }

            block.branch(value);

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn rol(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let count = self.operand_load(&mut block, &detail.operands[1])?;

            let mut count = match count.bits() {
                8 => Expr::and(count.clone(), expr_const(0x7, count.bits()))?,
                16 => Expr::and(count.clone(), expr_const(0xf, count.bits()))?,
                32 => Expr::and(count.clone(), expr_const(0x1f, count.bits()))?,
                64 => Expr::and(count.clone(), expr_const(0x3f, count.bits()))?,
                _ => bail!("Unsupported rol bits {}", count.bits())
            };

            if count.bits() < lhs.bits() {
                count = Expr::zext(lhs.bits(), count)?;
            }

            let shift_left_bits = count;
            let shift_right_bits = Expr::sub(
                expr_const(lhs.bits() as u64, lhs.bits()),
                shift_left_bits.clone()
            )?;

            let result = Expr::or(
                Expr::shl(lhs.clone(), shift_left_bits.clone())?,
                Expr::shr(lhs.clone(), shift_right_bits.clone())?
            )?;

            // CF is the bit sent from one end to the other. In our case, it should be LSB of result
            block.assign(scalar("CF", 1), Expr::shr(
                result.clone(),
                expr_const(result.bits() as u64 - 1, result.bits())
            )?);

            // OF is XOR of two most-significant bits of result
            block.assign(scalar("OF", 1), Expr::xor(
                Expr::trun(1, Expr::shr(result.clone(),
                                        expr_const(result.bits() as u64 - 1,
                                                   result.bits()))?)?,
                Expr::trun(1, Expr::shr(result.clone(),
                                        expr_const(result.bits() as u64 - 2,
                                                   result.bits()))?)?
            )?);

            // SF/ZF are unaffected

            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn ror(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let count = self.operand_load(&mut block, &detail.operands[1])?;

            let mut count = match count.bits() {
                8 => Expr::and(count.clone(), expr_const(0x7, count.bits()))?,
                16 => Expr::and(count.clone(), expr_const(0xf, count.bits()))?,
                32 => Expr::and(count.clone(), expr_const(0x1f, count.bits()))?,
                64 => Expr::and(count.clone(), expr_const(0x3f, count.bits()))?,
                _ => bail!("Unsupported ror bits {}", count.bits())
            };

            if count.bits() < lhs.bits() {
                count = Expr::zext(lhs.bits(), count)?;
            }

            let shift_right_bits = count;
            let shift_left_bits = Expr::sub(
                expr_const(lhs.bits() as u64, lhs.bits()),
                shift_right_bits.clone()
            )?;

            let result = Expr::or(
                Expr::shl(lhs.clone(), shift_left_bits.clone())?,
                Expr::shr(lhs.clone(), shift_right_bits.clone())?
            )?;

            // CF is the bit sent from one end to the other. In our case, it should be MSB of result
            block.assign(scalar("CF", 1), Expr::shr(
                result.clone(),
                expr_const(result.bits() as u64 - 1, result.bits())
            )?);

            // OF is XOR of two most-significant bits of result
            block.assign(scalar("OF", 1), Expr::xor(
                Expr::trun(1, Expr::shr(result.clone(),
                                        expr_const(result.bits() as u64 - 1,
                                                   result.bits()))?)?,
                Expr::trun(1, Expr::shr(result.clone(),
                                        expr_const(result.bits() as u64 - 2,
                                                   result.bits()))?)?
            )?);

            // SF/ZF are unaffected

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn sahf(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let ax = self.get_register(x86_reg::X86_REG_AX)?.get()?;

            let cf = Expr::trun(1, ax.clone())?;
            // let pf = Expr::trun(1, Expr::shr(2, ax.clone())?)?;
            // let af = Expr::trun(1, Expr::shr(4, ax.clone())?)?;
            let zf = Expr::trun(1, Expr::shr(expr_const(6, 16), ax.clone())?)?;
            let sf = Expr::trun(1, Expr::shr(expr_const(7, 16), ax.clone())?)?;

            block.assign(scalar("CF", 1), cf);
            // block.assign(scalar("PF", 1), pf);
            // block.assign(scalar("AF", 1), af);
            block.assign(scalar("ZF", 1), zf);
            block.assign(scalar("SF", 1), sf);

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }



    pub fn sar(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::zext(lhs.bits(), rhs)?;
            }

            // Create the mask we apply if that lhs is signed
            let mask = Expr::shl(expr_const(1, lhs.bits()), rhs.clone())?;
            let mask = Expr::sub(mask, expr_const(1, lhs.bits()))?;
            let mask = Expr::shl(mask, Expr::sub(
                expr_const(lhs.bits() as u64, lhs.bits()),
                rhs.clone())?
            )?;

            // Multiple the mask by the sign bit
            let expr = Expr::shr(lhs.clone(),
                                 expr_const(lhs.bits() as u64 - 1,
                                            lhs.bits()))?;
            let expr = Expr::mul(mask, expr)?;

            // Do the SAR
            let expr = Expr::or(expr, Expr::shr(lhs.clone(), rhs.clone())?)?;
            let temp = block.temp(lhs.bits());
            block.assign(temp.clone(), expr);

            // OF is the last bit shifted out
            block.assign(scalar("OF", 1), expr_const(0, 1));

            self.set_zf(&mut block, temp.clone().into())?;
            self.set_sf(&mut block, temp.clone().into())?;
            self.set_cf(&mut block, temp.clone().into(), lhs.clone())?;

            self.operand_store(&mut block, &detail.operands[0], temp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn sbb(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs)?;
            }

            let rhs = Expr::add(rhs.clone(),
                                Expr::zext(rhs.bits(), expr_scalar("CF", 1))?)?;
            let expr = Expr::sub(lhs.clone(), rhs.clone())?;

            // calculate flags
            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block, expr.clone(), lhs.clone(), rhs.clone())?;
            self.set_cf(&mut block, expr.clone(), lhs.clone())?;

            // store result
            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn scasb(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let al = self.get_register(x86_reg::X86_REG_AL)?;
        let di = self.get_register(x86_reg::X86_REG_DI)?.get_full()?;

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let temp = block.temp(8);
            block.load(temp.clone(), di.get()?);
            let expr = Expr::sub(al.get()?, temp.clone().into())?;

            // calculate flags
            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block,
                        expr.clone(),
                        al.get()?,
                        temp.clone().into())?;
            self.set_cf(&mut block, expr.clone(), al.get()?)?;

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            di.set(&mut block, Expr::add(di.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            di.set(&mut block, Expr::sub(di.get()?,
                                         expr_const(1, self.mode().bits()))?)?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };

        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;


        Ok(())
    }


    pub fn scasw(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let ax = self.get_register(x86_reg::X86_REG_AX)?;
        let di = self.get_register(x86_reg::X86_REG_DI)?.get_full()?;

        let head_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let temp = block.temp(16);
            block.load(temp.clone(), di.get()?);
            let expr = Expr::sub(ax.get()?, temp.clone().into())?;

            // calculate flags
            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;
            self.set_of(&mut block,
                        expr.clone(),
                        ax.get()?,
                        temp.clone().into())?;
            self.set_cf(&mut block, expr.clone(), temp.clone().into())?;

            block.index()
        };

        let inc_index = {
            let mut block = control_flow_graph.new_block()?;

            di.set(&mut block, Expr::add(di.get()?,
                                         expr_const(2, self.mode().bits()))?)?;

            block.index()
        };

        let dec_index = {
            let mut block = control_flow_graph.new_block()?;

            di.set(&mut block, Expr::sub(di.get()?,
                                         expr_const(2, self.mode().bits()))?)?;

            block.index()
        };

        let tail_index = {
            control_flow_graph.new_block()?.index()
        };

        control_flow_graph.conditional_edge(
            head_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;

        control_flow_graph.conditional_edge(
            head_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;

        control_flow_graph.unconditional_edge(inc_index, tail_index)?;
        control_flow_graph.unconditional_edge(dec_index, tail_index)?;

        control_flow_graph.set_entry(head_index)?;
        control_flow_graph.set_exit(tail_index)?;


        Ok(())
    }


    pub fn setcc(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            let expr = self.cc_condition()?;

            self.operand_store(&mut block,
                               &detail.operands[0],
                               Expr::zext(8, expr)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn shl(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::zext(lhs.bits(), rhs)?;
            }

            // Do the SHL
            let expr = Expr::shl(lhs.clone(), rhs.clone())?;

            // CF is the last bit shifted out
            // This will give us a bit mask if rhs is not equal to zero
            let non_zero_mask = Expr::sub(
                expr_const(0, rhs.bits()),
                Expr::zext(rhs.bits(),
                           Expr::cmpneq(rhs.clone(),
                                        expr_const(0, rhs.bits()))?)?
            )?;
            // This shifts lhs left by (rhs - 1)
            let cf = Expr::shl(lhs.clone(),
                               Expr::sub(rhs.clone(),
                                         expr_const(1, rhs.bits()))?)?;
            // Apply mask
            let cf = Expr::trun(1, Expr::and(cf, non_zero_mask)?)?;
            block.assign(scalar("CF", 1), cf.clone());

            // OF is set if most significant bit of result is equal to OF
            let of = Expr::cmpeq(
                cf,
                Expr::trun(
                    1,
                    Expr::shr(
                        expr.clone(),
                        expr_const(expr.bits() as u64 - 1, expr.bits())
                    )?
                )?
            )?;
            block.assign(scalar("OF", 1), of);

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn shr(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::zext(lhs.bits(), rhs)?;
            }

            // Do the SHR
            let expr = Expr::shr(lhs.clone(), rhs.clone())?;

            // CF is the last bit shifted out
            // This will give us a bit mask if rhs is not equal to zero
            let non_zero_mask = Expr::sub(
                expr_const(0, rhs.bits()),
                Expr::zext(rhs.bits(),
                           Expr::cmpneq(rhs.clone(),
                                        expr_const(0, rhs.bits()))?)?
            )?;
            // This shifts lhs right by (rhs - 1)
            let cf = Expr::shr(lhs.clone(),
                               Expr::sub(rhs.clone(),
                                         expr_const(1, rhs.bits()))?)?;
            // Apply mask
            let cf = Expr::trun(1, Expr::and(cf, non_zero_mask)?)?;
            block.assign(scalar("CF", 1), cf);

            // OF set to most significant bit of the original operand
            block.assign(scalar("OF", 1), Expr::trun(
                1,
                Expr::shr(lhs.clone(), expr_const(lhs.bits() as u64 - 1,
                                                  lhs.bits()))?
            )?);

            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr.clone())?;

            self.operand_store(&mut block, &detail.operands[0], expr)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn shld(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;
            let count = self.operand_load(&mut block, &detail.operands[2])?;

            let tmp = Expr::or(
                Expr::shl(Expr::zext(dst.bits() * 2, dst.clone())?,
                          expr_const(dst.bits() as u64, dst.bits() * 2))?,
                Expr::zext(dst.bits() * 2, rhs)?
            )?;

            let result = Expr::shl(tmp.clone(),
                                   Expr::zext(tmp.bits(),
                                   count.clone())?)?;

            let cf = Expr::trun(
                1,
                Expr::shl(
                    tmp.clone(),
                    Expr::zext(
                        tmp.bits(),
                        Expr::sub(count.clone(), expr_const(1, count.bits()))?
                    )?
                )?
            )?;

            block.assign(scalar("CF", 1), cf);

            self.set_zf(&mut block, result.clone())?;
            self.set_sf(&mut block, result.clone())?;

            self.operand_store(&mut block,
                               &detail.operands[0],
                               Expr::trun(dst.bits(), result)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn shrd(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let dst = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;
            let count = self.operand_load(&mut block, &detail.operands[2])?;

            let tmp = Expr::or(
                Expr::zext(dst.bits() * 2, dst.clone())?,
                Expr::shl(Expr::zext(dst.bits() * 2, rhs)?,
                          expr_const(dst.bits() as u64, dst.bits() * 2))?
            )?;

            let result = Expr::shr(tmp.clone(),
                                   Expr::zext(tmp.bits(), count.clone())?)?;

            let cf = Expr::trun(
                1,
                Expr::shr(
                    tmp.clone(),
                    Expr::zext(
                        tmp.bits(),
                        Expr::sub(count.clone(), expr_const(1, count.bits()))?
                    )?
                )?
            )?;

            block.assign(scalar("CF", 1), cf);

            self.set_zf(&mut block, result.clone())?;
            self.set_sf(&mut block, result.clone())?;

            self.operand_store(&mut block,
                               &detail.operands[0],
                               Expr::trun(dst.bits(), result)?)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn stc(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let block_index = {
            let block = control_flow_graph.new_block()?;
            block.assign(scalar("CF", 1), expr_const(1, 1));
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn std(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let block_index = {
            let block = control_flow_graph.new_block()?;
            block.assign(scalar("DF", 1), expr_const(1, 1));
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn sti(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let block_index = {
            let block = control_flow_graph.new_block()?;
            block.assign(scalar("IF", 1), expr_const(1, 1));
            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn stos(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let di = self.get_register(x86_reg::X86_REG_DI)?.get_full()?;

        // create a block for this instruction
        let (block_index, bits) = {
            let mut block = control_flow_graph.new_block()?;

            let src = self.operand_load(&mut block, &detail.operands[1])?;
            let bits = src.bits();
            self.operand_store(&mut block, &detail.operands[0], src)?;

            (block.index(), bits as u64)
        };

        let inc_index = {
            let mut inc_block = control_flow_graph.new_block()?;;

            di.set(&mut inc_block,
                   Expr::add(di.get()?,
                             expr_const(bits / 8, self.mode().bits()))?)?;

            inc_block.index()
        };

        let dec_index = {
            let mut dec_block = control_flow_graph.new_block()?;;

            di.set(&mut dec_block,
                   Expr::sub(di.get()?,
                             expr_const(bits / 8, self.mode().bits()))?)?;

            dec_block.index()
        };

        let terminating_index = {
            control_flow_graph.new_block()?.index()
        };

        control_flow_graph.conditional_edge(
            block_index,
            inc_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(0, 1))?
        )?;
        control_flow_graph.conditional_edge(
            block_index,
            dec_index,
            Expr::cmpeq(expr_scalar("DF", 1), expr_const(1, 1))?
        )?;
        control_flow_graph.unconditional_edge(inc_index, terminating_index)?;
        control_flow_graph.unconditional_edge(dec_index, terminating_index)?;

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(terminating_index)?;

        Ok(())
    }


    pub fn sub(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs)?;
            }

            let result = block.temp(lhs.bits());
            block.assign(result.clone(), Expr::sub(lhs.clone(), rhs.clone())?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            self.set_of(&mut block,
                        result.clone().into(),
                        lhs.clone(),
                        rhs.clone())?;
            self.set_cf(&mut block, result.clone().into(), lhs.clone())?;

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn syscall(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            block.intrinsic(
            Intrinsic::new(
                "syscall",
                "syscall",
                Vec::new(),
                None,
                None,
                self.instruction().bytes.get(0..4).unwrap().to_vec()
            ));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn sysenter(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        // create a block for this instruction
        let block_index = {
            let block = control_flow_graph.new_block()?;

            block.intrinsic(
            Intrinsic::new(
                "sysenter",
                "sysenter",
                Vec::new(),
                None,
                None,
                self.instruction().bytes.get(0..4).unwrap().to_vec()
            ));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn test(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let expr = Expr::and(lhs.clone(), rhs.clone())?;

            // calculate flags
            self.set_zf(&mut block, expr.clone())?;
            self.set_sf(&mut block, expr)?;
            block.assign(scalar("CF", 1), expr_const(0, 1));
            block.assign(scalar("OF", 1), expr_const(0, 1));;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn ud2(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            block.intrinsic(Intrinsic::new(
                "ud2",
                "ud2",
                Vec::new(),
                None,
                None,
                self.instruction().bytes.get(0..2).unwrap().to_vec()
            ));

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn xadd(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let result = block.temp(lhs.bits());

            // perform addition
            block.assign(result.clone(), Expr::add(lhs.clone(), rhs.clone())?);

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            self.set_of(&mut block,
                        result.clone().into(),
                        lhs.clone(),
                        rhs.clone())?;
            self.set_cf(&mut block, result.clone().into(), lhs.clone())?;

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;
            self.operand_store(&mut block, &detail.operands[1], rhs)?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn xchg(
        &self,
        control_flow_graph: &mut ControlFlowGraph
    ) -> Result<()> {

        let detail = self.details()?;

        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let rhs = self.operand_load(&mut block, &detail.operands[1])?;

            let tmp = block.temp(lhs.bits());
            block.assign(tmp.clone(), lhs.clone());

            self.operand_store(&mut block, &detail.operands[0], rhs)?;
            self.operand_store(&mut block, &detail.operands[1], tmp.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }


    pub fn xor(&self, control_flow_graph: &mut ControlFlowGraph) -> Result<()> {

        let detail = self.details()?;

        // create a block for this instruction
        let block_index = {
            let mut block = control_flow_graph.new_block()?;

            // get operands
            let lhs = self.operand_load(&mut block, &detail.operands[0])?;
            let mut rhs = self.operand_load(&mut block, &detail.operands[1])?;

            if lhs.bits() != rhs.bits() {
                rhs = Expr::sext(lhs.bits(), rhs)?;
            }

            let result = block.temp(lhs.bits());

            // In the event lhs and rhs are the same, this is actually an
            // assignment of zero. Treat it as such.
            if lhs == rhs {
                block.assign(result.clone(), expr_const(0, result.bits()));
            }
            else {
                block.assign(
                    result.clone(),
                    Expr::xor(lhs.clone(), rhs.clone())?);
            }

            // calculate flags
            self.set_zf(&mut block, result.clone().into())?;
            self.set_sf(&mut block, result.clone().into())?;
            block.assign(scalar("CF", 1), expr_const(0, 1));
            block.assign(scalar("OF", 1), expr_const(0, 1));;

            // store result
            self.operand_store(&mut block, &detail.operands[0], result.into())?;

            block.index()
        };

        control_flow_graph.set_entry(block_index)?;
        control_flow_graph.set_exit(block_index)?;

        Ok(())
    }
}