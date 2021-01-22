// mod check2;
#[path = "../test/check2.rs"]  mod check2;

pub fn print(){
	println!("in check1");
}

pub fn checktwo(){
	check2::print();
}




