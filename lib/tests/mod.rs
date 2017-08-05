#[cfg(test)] use il;
#[cfg(test)] use executor;

mod simple_0;

#[test]
fn il_constants () {
    let expr = il::Expression::add(il::expr_const(10, 32), il::expr_const(20, 32)).unwrap();
    assert_eq!(executor::constants_expression(&expr).unwrap().value(), 30);
}