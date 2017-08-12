#[cfg(test)] use il;
#[cfg(test)] use engine;
#[cfg(test)] use executor;

mod simple_0;

#[test]
fn il_constants () {
    let expr = il::Expression::add(il::expr_const(10, 32), il::expr_const(20, 32)).unwrap();
    assert_eq!(executor::constants_expression(&expr).unwrap().value(), 30);
}

#[test]
fn simplify_expression () {
    let expr = il::Expression::add(
        il::Expression::add(
            il::expr_const(100, 32),
            il::expr_const(50, 32),
        ).unwrap(),
        il::expr_scalar("test", 32)
    ).unwrap();

    let expr = engine::simplify_expression(&expr).unwrap();

    if let il::Expression::Add(lhs, _) = expr {
        if let il::Expression::Constant(c) = *lhs {
            assert!(c.value() == 150);
        }
        else {
            assert!(false);
        }
    }
    else {
        assert!(false);
    }
}