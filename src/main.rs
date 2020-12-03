//this is an implementation in rust of the chacha20 using rfc 8439 as a guide.
use std::mem::transmute;
use std::convert::TryInto;



//quarter round calculation
fn quarter_round(state: &mut [u32], x: usize, y: usize, z: usize, w: usize){
	let mut temp_a = state[x];
	let mut temp_b = state[y];
	let mut temp_c = state[z];
	let mut temp_d = state[w];
	
	//wrapping add is the an addition without overflowing 32 bits
	//1 
	temp_a = temp_a.wrapping_add(temp_b);
	temp_d = temp_d ^ temp_a;
	temp_d = temp_d.rotate_left(16);
	
	//2
	temp_c = temp_c.wrapping_add(temp_d);
	temp_b = temp_b ^ temp_c;
	temp_b = temp_b.rotate_left(12);
	
	//3
	temp_a = temp_a.wrapping_add(temp_b);
	temp_d = temp_d ^ temp_a;
	temp_d = temp_d.rotate_left(8);
	
	//4
	temp_c = temp_c.wrapping_add(temp_d);
	temp_b = temp_b ^ temp_c;
	temp_b = temp_b.rotate_left(7);
	
	
	state[x] = temp_a;
	state[y] = temp_b;
	state[z] = temp_c;
	state[w] = temp_d;
}

//build the block for the quarter rounds
fn build_state(state: &mut [u32], key: &String, counter: u32, nonce: &String){
	
	//this are the four constants
	state[0] = 0x61707865u32;
	state[1] = 0x3320646eu32;
	state[2] = 0x79622d32u32;
	state[3] = 0x6b206574u32;
	
	//this is the key
	let key_u32 = hex_str_to_u32s(&key);
	state[4] = key_u32[0];
	state[5] = key_u32[1];
	state[6] = key_u32[2];
	state[7] = key_u32[3];
	state[8] = key_u32[4];
	state[9] = key_u32[5];
	state[10] = key_u32[6];
	state[11] = key_u32[7];
	state[12] = counter;
	
	//this is the nonce
	let nonce_u32 = hex_str_to_u32s(&nonce);
	state[13] = nonce_u32[0];
	state[14] = nonce_u32[1];
	state[15] = nonce_u32[2];
	
}

//convert string hex into 32bit integers in little endian order
fn hex_str_to_u32s(str: &String) -> Vec<u32>{
	
	let cap = str.len()/8;
	let mut vec = Vec::with_capacity(cap);
	let mut slice = &str[..]; 
	let mut tmp_str= String::new();
	let mut i = 0;
	
	while i < str.len() {
		if i%8 == 0 && i !=0  {
			
			vec.push(u32::from_str_radix(&tmp_str,16).unwrap());
			tmp_str.clear();
			
		} 
		
		slice = &str[i..i+2];
		tmp_str.insert_str(0,slice);
		i = i+2;
		
	}
	
	vec.push(u32::from_str_radix(&tmp_str,16).unwrap());
	vec
	
}

//the rounds
fn inner_block(mut state: &mut [u32]) {
	
	quarter_round(&mut state, 0, 4, 8, 12);
	quarter_round(&mut state, 1, 5, 9, 13);
	quarter_round(&mut state, 2, 6, 10, 14);
	quarter_round(&mut state, 3, 7, 11, 15);
	quarter_round(&mut state, 0, 5, 10, 15);
	quarter_round(&mut state, 1, 6, 11, 12);
	quarter_round(&mut state, 2, 7, 8, 13);
	quarter_round(&mut state, 3, 4, 9, 14);
	
}

//serializing the state
fn serialize(state: &mut [u32]) -> Vec<u8>{
	
	let mut serialized_state: Vec<u8> = Vec::new();
	
	for i in 0..16 {
		
		let bytes: [u8; 4] = unsafe {transmute(state[i].to_be())};
		serialized_state.push(bytes[3]);
		serialized_state.push(bytes[2]);
		serialized_state.push(bytes[1]);
		serialized_state.push(bytes[0]);	
	}
	
	serialized_state
	
}

//the chacha20 block function
fn chacha20_block(key: &String, counter: u32, nonce: &String) -> Vec<u8>{
	
	let mut state: [u32;16] = [0;16];
	build_state(&mut state,key,counter,nonce);
	let  working_state = state;
	
	for _i in 0..10 {
		inner_block(&mut state);
	}
	
	for i in 0..16 {
		
		state[i] = state[i].wrapping_add(working_state[i]);
	}
	
	let serialized_state = serialize(&mut state);
	serialized_state
	
}

//the chacha20 encryption algorithm
fn chacha20_encrypt(key: String, counter: u32, nonce: String, plaintext: String) -> Vec<u8>{
	
	let plaintext_bytes = plaintext.as_bytes();
	let mut j: u32 = 0;
	let mut encrypted_message: Vec<u8> = Vec::new(); 
	
	for i in 0..(plaintext_bytes.len()/64) {
		
		let key_stream = chacha20_block(&key, counter+j, &nonce);
		let block = &plaintext_bytes[(i*64)..(i*64+64)];
		let mut tmp: Vec<u8> = key_stream.iter().zip(block.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
		encrypted_message.append(&mut tmp);
		j += 1;
	
	}
	
	if (plaintext_bytes.len()%64) != 0 {
		
		let i = plaintext_bytes.len()/64;
		j = (i as u32).try_into().unwrap();
		let key_stream = chacha20_block(&key, counter+j, &nonce);
		let block = &plaintext_bytes[(i*64)..plaintext_bytes.len()];
		let mut tmp: Vec<u8> = key_stream.iter().zip(block.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
		encrypted_message.append(&mut tmp);
		
	} 
	
	encrypted_message
	
}

//this is used for debugging
//missing implementation of i/o operations
//used a test vector sugested in rfc8439
fn main(){
	
	let key = String::from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	let nonce = String::from("000000000000004a00000000");
	let plaintext = String::from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");	
	let encrypted_message = chacha20_encrypt(key,1,nonce, plaintext);
	let s_encrypted_message = String::from_utf8_lossy(&encrypted_message);
	println!("{:?}", s_encrypted_message);
	

}