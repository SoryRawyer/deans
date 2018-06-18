use std::net::{UdpSocket};
use std::env;

fn main(){
    // DNS -> port 53
    // 1. construct DNS query (header + question)
    //   question : domain + type + class (class is "IN" for internet applications)
    // 2. parse response (header + question + answers)

    let socket = UdpSocket::bind("0.0.0.0:34254").expect("somethign qent wrong [sic]");

    //let domain: &str = env::args().collect().get(0).expect("No domain arg supplied");

    let args: Vec<String> = env::args().collect();
    let domain = args.get(1).expect("No domain supplied");
    let header = DnsHeader{
        id: u16::to_be(1025),
        query_response: false,
        opcode: 0,
        authoritative_answer: false,
        truncation: false,
        recursion_desired: true,
        recursion_available: false,
        rcode: 0,
        question_count: 1,
        answer_count: 0,
        auth_count: 0,
        add_rec_count: 0
    };
    let question = DnsQuestion {
        domain: domain.to_owned(),
        question_type: 1u16,
        question_class: 1u16
    };
    let mut query: Vec<u8> = header.serialize().to_vec();
    let mut serialized_question = question.serialize();
    query.append(&mut serialized_question);

    socket.connect("10.0.0.1:53").expect("could not connect");
    // socket.send_to(query.as_slice(), "8.8.8.8:53").expect("send_to failed");
    socket.send(query.as_slice()).expect("send failed");

    let mut response_bytes: Vec<u8> = Vec::new();


        let mut buf = [0; 1500];
        match socket.recv(&mut buf) {
            Ok(received) => {
                response_bytes.extend(&buf[..received]);

            }
            Err(e) => println!("recv function failed: {:?}", e),
        }  
    
    let answer_start_index: usize = 12 + question.serialize().len();
    // println!("response bytes: {:?}", response_bytes);
    // println!("response bytes, starting at {:?}, {:?}", answer_start_index, &response_bytes[answer_start_index..]);

    println!("{}", get_ip_from_response(&response_bytes[answer_start_index..]));
    // println!("{}", get_ip_from_response(response_bytes, answer_start_index));

}

fn get_ip_from_response(response_bytes: &[u8]) -> String {
    // response will be header + question + answer RRs
    // we know length of header and question

    let rdata_length = response_bytes[11];
    let data_type = response_bytes[3];

    if data_type == 6 {
        return String::from("SOA (not found)");
    }

    if data_type != 1 {
        panic!("Non A-Records unsupported");
    }
    if rdata_length == 4 {
        let octet_list: Vec<String> = response_bytes[12..16].iter().map(|byte| byte.to_string()).collect();
        return octet_list.join(".");

    } else {
        panic!("Abort!")
    }

}

// DNS Headers are always 12 bytes
pub struct DnsHeader {
    // first two bytes
    id: u16,
    // third byte
    query_response: bool,
    opcode: u8,
    authoritative_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    // fourth byte
    recursion_available: bool,
    // zeros: three bits
    rcode: u8,
    // fifth and sixth bytes
    question_count: u16,
    // 7 and 8 bytes
    answer_count: u16,
    // 9 and 10 bytes
    auth_count: u16,
    // 11 and 12 bytes
    add_rec_count: u16
}

impl DnsHeader {
    fn serialize(self) -> [u8; 12] {
        let mut byte_array: [u8; 12]= [0; 12];
        byte_array[0] = (self.id >> 8) as u8;
        byte_array[1] = self.id as u8;

        byte_array[2] = 0 as u8;
        byte_array[2]  = byte_array[2] | ((self.query_response as u8) << 7);
        byte_array[2] = byte_array[2] | self.opcode << 3;
        byte_array[2] = byte_array[2] | ((self.authoritative_answer as u8) << 2);
        byte_array[2] = byte_array[2] | ((self.truncation as u8) << 1);
        byte_array[2] = byte_array[2] | (self.recursion_desired as u8);

        byte_array[3] = 0 as u8;
        byte_array[3]  = byte_array[3] | ((self.recursion_available as u8) << 7);
        byte_array[3] = byte_array[3] | (self.rcode as u8);

        byte_array[4] = (self.question_count >> 8) as u8;
        byte_array[5] = self.question_count as u8;

        byte_array[6] = (self.answer_count >> 8) as u8;
        byte_array[7] = self.answer_count as u8;

        byte_array[8] = (self.auth_count >> 8) as u8;
        byte_array[9] = self.auth_count as u8;

        byte_array[10] = (self.add_rec_count >> 8) as u8;
        byte_array[11] = self.add_rec_count as u8;

        return byte_array;
    }
}

pub struct DnsQuestion {
    domain: String,
    question_type: u16,
    question_class: u16
}

impl DnsQuestion {
  fn serialize(&self) -> Vec<u8> {
      let mut byte_vec: Vec<u8> = Vec::new();
      let mut parsed_domain = self._parse_domain();
      byte_vec.append(&mut parsed_domain);
 
      byte_vec.push((self.question_type >> 8) as u8);
      byte_vec.push((self.question_type) as u8);

      byte_vec.push((self.question_class >> 8) as u8);
      byte_vec.push((self.question_class) as u8);

      byte_vec
  }

  fn _parse_domain(&self) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for piece in self.domain.split(".") {
        result.push(piece.len() as u8);
        for c in piece.chars() {
            result.push(c as u8);
        }
    }
    result.push(0u8);
    result
  }

}


#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_serialize_dns_header() {
        let head = DnsHeader{
            id: 1025,
            query_response: true,
            opcode: 0,
            authoritative_answer: true,
            truncation: true,
            recursion_desired: true,
            recursion_available: true,
            rcode: 0,
            question_count: 0,
            answer_count: 0,
            auth_count: 0,
            add_rec_count: 0
        };
        let serialized_dns_header = head.serialize();
        assert_eq!(serialized_dns_header[0], 4);
        assert_eq!(serialized_dns_header[1], 1);
        // third byte: 10000111
        assert_eq!(serialized_dns_header[2], 135);
        assert_eq!(serialized_dns_header[3], 128);
    }

    #[test]
    fn test_serialize_dns_question() {
        let question = DnsQuestion {
            domain: String::from("google.com"),
            question_type: 1025,
            question_class: 1025
        };

        let serialized_question = question.serialize();
        let correct_domain_part: [u8; 11]= [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109];
        assert_eq!(serialized_question[0..11], correct_domain_part);
        assert_eq!(serialized_question[11..13], [4,1]);
        assert_eq!(serialized_question[13..15], [4,1]);

    }
}
