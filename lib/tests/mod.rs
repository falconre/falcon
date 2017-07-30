use il;
use executor;

#[test]
fn il_constants () {
    let expr = il::Expression::add(il::expr_const(10, 32), il::expr_const(20, 32)).unwrap();
    assert_eq!(executor::constants_expression(&expr).unwrap().value(), 30);
}