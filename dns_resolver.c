/* [=====================================] */
/* [ ------> DNS RESOLVING TOOL  <------ ] */
/* [==== >> | 27.11.2024  14:45 | << ====] */
/* [==== >>    | Version 1.0 |    << ====] */
/* [=====================================] */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* Information: https://habr.com/ru/articles/478652/ */
typedef unsigned int __do53_ttl;
typedef unsigned short __do53_type;
typedef unsigned short __do53_class;
typedef unsigned short __do53_rdlenght;
typedef unsigned short __do53_count;
typedef unsigned short __do53_id;
typedef unsigned short __do53_flags;

typedef struct 
{
	char *_name;

	__do53_type _type;
	__do53_class _class;
	__do53_ttl _ttl;
	__do53_rdlenght _rdlenght;

	unsigned char *_rdata;
} _do53;


void __canonicalize(char *_name) 
{
	int name_lenght, get_counter;

	if (strcmp(_name, ".") == 0) 
    {
		return;
	}

	name_lenght = strlen(_name);

	if (_name[name_lenght - 1] == '.') 
    {
		_name[name_lenght - 1] = '\0';
	}

	for (get_counter = 0; get_counter < name_lenght; get_counter++) 
    {
		if (_name[get_counter] >= 'A' && _name[get_counter] <= 'Z') 
        {
			_name[get_counter] += 32;
		}
	}
}

int __ascii_convertation_to_wire(char *_name, unsigned char *_wire) 
{
	 unsigned char *wire_start = _wire;
	 unsigned char *current_counter = _wire;

	 *current_counter = 0;

	 _wire++;

	 while (*_name != 0x00)
     {
		 if (*_name == '.')
         {
			 current_counter = _wire;
		 }
         else
         {
			 *_wire = *_name;
			 (*current_counter)++;
		 }

		 _wire++;
		 _name++;
	 }
	 *_wire = 0x00;

	 return strlen(wire_start);
}

int __ascii_convertation_from_wire(unsigned char *_wire, int *_index, char* _name) 
{
	 int _get_lenght = 1;
	 char *name_start = _name;
	 int get_counter = *_index;

	 unsigned char chunk_size = _wire[get_counter] & 0xFF;

	 get_counter++;

	 while (chunk_size)
     {
		if ((chunk_size & 0xC0) == 0xC0)
        {
			int compressed_index = (_wire[get_counter] & 0xff);
			int sub_length = __ascii_convertation_from_wire(_wire, &compressed_index, _name);

			_name += sub_length;

			get_counter++;
			_get_lenght++;

			chunk_size = _wire[get_counter];

			continue;
		}

		for (int get_local_counter = 0; get_local_counter < chunk_size; get_local_counter++)
        {
			_get_lenght++;

			*_name = _wire[get_counter+get_local_counter];

			_name++;
		}

		unsigned char old_cs_flag = chunk_size;

		chunk_size = _wire[get_counter+chunk_size];
		get_counter = get_counter+old_cs_flag + 1;

		if (chunk_size)
        {
			*_name = '.';

			_name++;

			_get_lenght++;
		}
	 }
	 *_name = 0x00;

	 return _get_lenght;
}

_do53* __do53_resource_record_from_wire(unsigned char* _query_start, unsigned char **_get_answer, int _query_only) 
{
	 _do53* get_result = malloc(sizeof(_do53));

	char *owner_name = malloc(1024);

	int get_local_counter = 0;

	if ((**_get_answer & 0xC0) == 0xC0)
    {
		get_local_counter = (*_get_answer)[1];

		__ascii_convertation_from_wire(_query_start, &get_local_counter, owner_name);

		get_result->_name = owner_name;
		get_result->_type = ((*_get_answer)[2] << 8) | (*_get_answer)[3];
		get_result->_class = ((*_get_answer)[4] << 8) | (*_get_answer)[5];
		get_result->_ttl = ((*_get_answer)[6] << 24) | ((*_get_answer)[7] << 16) | ((*_get_answer)[8] << 8) | ((*_get_answer)[9]);
		get_result->_rdlenght = ((*_get_answer)[10] << 8) | (*_get_answer)[11];
		get_result->_rdata = &((*_get_answer)[12]);

		(*_get_answer) += 12 + get_result->_rdlenght;

		return get_result;
	} 
    else
    {
		unsigned k_number = (*_get_answer) - _query_start;

		int name_lenght = __ascii_convertation_from_wire(_query_start, &k_number, owner_name);

		get_result->_name = owner_name;
		get_result->_type = ((*_get_answer)[name_lenght] << 8) | (*_get_answer)[name_lenght + 1];
		get_result->_class = ((*_get_answer)[name_lenght + 2] << 8) | (*_get_answer)[name_lenght + 3];
		get_result->_ttl = ((*_get_answer)[name_lenght + 4] << 24) | ((*_get_answer)[name_lenght + 5] << 16) | ((*_get_answer)[name_lenght + 6] << 8) | ((*_get_answer)[name_lenght + 7]);
		get_result->_rdlenght = ((*_get_answer)[name_lenght + 8] << 8) | (*_get_answer)[name_lenght + 9];
		get_result->_rdata = (*_get_answer) + name_lenght + 10;

		(*_get_answer) += name_lenght + 10 + get_result->_rdlenght;

		return get_result;
	}
}

unsigned short __do53_query(char *_qname, __do53_type _qtype, unsigned char *_wire) 
{
	_wire[0] = rand();
	_wire[1] = rand();
	_wire[2] = 0x01;
	_wire[3] = 0x00;
	_wire[4] = 0x00;
	_wire[5] = 0x01;
	_wire[6] = 0x00;
	_wire[7] = 0x00;
	_wire[8] = 0x00;
	_wire[9] = 0x00;
	_wire[10] = 0x00;
	_wire[11] = 0x00;

	int query_lenght = __ascii_convertation_to_wire(_qname, &(_wire[12]));
	int nextLoc = 12 + query_lenght + 1;

	_wire[nextLoc] = 0x00;
	_wire[++nextLoc] = 0x01;
	_wire[++nextLoc] = 0x00;
	_wire[++nextLoc] = 0x01;

	return nextLoc + 1;
}

void __wire_to_string(char *_wire, int _ip_lenght, char *_ip_address)
{
	int get_counter = 0;
	char* current_state_ip = _ip_address;

	while (_ip_lenght)
    {
		int chars = sprintf(current_state_ip, (_ip_lenght == 1) ? "%u":"%u.", (_wire[get_counter] & 0xff));

		current_state_ip += chars; 

		get_counter++;

		_ip_lenght--;
	}
	current_state_ip = 0x00;
}

char *__do53_answer(char *_qname, __do53_type _qtype, unsigned char *_wire, char *_get_answer) 
{
	 uint16_t total_id = (_wire[0] << 8) | _wire[1];
	 uint16_t total_flag = (_wire[2] << 8) | _wire[3];
	 uint16_t total_question = (_wire[4] << 8) | _wire[5];
	 uint16_t total_answer = (_wire[6] << 8) | _wire[7];
	 uint16_t total_authority = (_wire[8] << 8) | _wire[9];
	 uint16_t total_additional = (_wire[10] << 8) | _wire[11];

	 char *_query_start = &(_wire[0]);

	 unsigned char name_buffer[512];

	 int get_counter = 12;
	 int query_name_length = __ascii_convertation_from_wire(_wire, &get_counter, name_buffer);

	 _qname = name_buffer;

	unsigned char *get_answer = _query_start + query_name_length + 17;

    for (int answer_number = 0; answer_number < total_answer; answer_number++)
    {
		_do53 do53_resource_record = *(__do53_resource_record_from_wire(_wire, &get_answer, 0));	

		if (strcmp(do53_resource_record._name, _qname) == 0 && do53_resource_record._type == _qtype)
        {
			char ip_string_data[90];

			__wire_to_string(do53_resource_record._rdata, do53_resource_record._rdlenght, ip_string_data);

			strncpy(_get_answer, ip_string_data, strlen(ip_string_data));

			return _get_answer;
		} 
        else if (strcmp(do53_resource_record._name, _qname) == 0 && do53_resource_record._type == 0x05)
        {
			int k_number = do53_resource_record._rdata - _wire;

			__ascii_convertation_from_wire(_wire, &k_number, _qname);

			__canonicalize(_qname);
		}
	}
	return NULL;
}

int __create_udp_packet(char* _rhost, short _rport) 
{
	struct sockaddr_in do53_resolver = 
    {
		.sin_family = AF_INET,
		.sin_port = htons(53),
		.sin_addr = inet_addr(_rhost)
	};

	int get_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (get_socket == -1) 
    {
		perror("[-] Error of _get_socket creation!\n");
		exit(EXIT_FAILURE);
	}

	if (connect(get_socket, (struct sockaddr*)&do53_resolver, sizeof(do53_resolver)) == -1) 
    {
		perror("[-] Error of _get_socket connection!\n");
		exit(EXIT_FAILURE);
	}
	return get_socket;
}

int __recv_packet(int _get_socket, unsigned char *_buffer, int _get_lenght) 
{
	unsigned char *get_pointer;

	int bytes_left;
	int bytes_read;

	get_pointer = _buffer;
	bytes_left = _get_lenght;
	bytes_read = recv(_get_socket, get_pointer, bytes_left, 0);

	if (bytes_read < 0) 
    {
		if (errno == EINTR) 
        {
			return -1;
		}
		else 
        {
			perror("[-] Error of reading packet data!\n");

            exit(EXIT_FAILURE);
		}
	}
	else if (bytes_read == 0) 
    {
		return -2;
	}

	get_pointer += bytes_read;
	bytes_left -= bytes_read;

	return bytes_read;
}

int __send_packet(int _get_socket, unsigned char* _buffer, int _get_lenght) 
{
	unsigned char* get_pointer;

	int bytes_left;
	int bytes_sent;

	get_pointer = _buffer;
	bytes_left = _get_lenght;

	while (bytes_left) 
    {
		bytes_sent = send(_get_socket, get_pointer, bytes_left, 0);

		if (bytes_sent < 0) 
        {
			if (errno == EINTR) 
            {
				continue;
			}
			else 
            {
				perror("[-] Error of sending packet data!\n");
                exit(EXIT_FAILURE);
			}
		}
		else if (bytes_sent == 0) 
        {
			return -1;
		}

		get_pointer += bytes_sent;
		bytes_left -= bytes_sent;
	}
	return 0;
}

int __send_udp_packet_data(unsigned char *_question, int _question_lenght, unsigned char *_get_answer, char *_rhost, unsigned short _rport) 
{
	 int get_socket = __create_udp_packet(_rhost, _rport);
	 int send_status = __send_packet(get_socket, _question, _question_lenght);

	 if (send_status != 0)
     {
		perror("[-] Error of sending packet data!\n");
        exit(EXIT_FAILURE);
	 }

	const int receive_buffer_data_lenght = 512;

	return __recv_packet(get_socket, _get_answer, receive_buffer_data_lenght);
}

char *__do53_resolve(char *_qname, char *_rhost) 
{
	unsigned char raw_data[1024];

	for (int get_counter = 0; get_counter < 1024; get_counter++)
    {
		raw_data[get_counter] = 0;
	}

	__do53_type _type = 0x01;

	int query_lenght = __do53_query(_qname, _type, raw_data);

	unsigned char *recv_buffer = malloc(1024);

	int bytes_read = __send_udp_packet_data(raw_data, query_lenght, recv_buffer, _rhost, 53);
	
	char *answer_buffer = malloc(1024);
	char *success = __do53_answer(_qname, _type, recv_buffer, answer_buffer);

	if (!success) 
    {
        return NULL;
    }
    else
    {
        char *return_pattern = answer_buffer;

	    return return_pattern;
    }
}

int main(int argc, char *argv[]) 
{
    srand(time(NULL));

    printf("[ ============================================================================================ ]\n");
    printf("[ ===================================== > DNS Resolver < ===================================== ]\n");
    printf("[ ========================================= # v 1.0 # ======================================== ]\n");
    printf("[ ============================================================================================ ]\n");

	if (argc != 3) 
    {
        printf("[*] Example of usage: sudo %s <Domain name> <DNS server IP address>\n", argv[0]);
		return 0;
	}
    else
    {
		char *_ip_address;

        char *get_domain_name = argv[1];
        char *get_dns_server_ip_address = argv[2];

        struct timespec start_time, end_time;

        double dns_latency;

        _ip_address = __do53_resolve(get_domain_name, get_dns_server_ip_address);
            
        printf("-------------------------------------------------\n");
        printf("[+] Resolving domain name: %s\n", get_domain_name);
		printf("[+] Resolved IP address: %s\n", _ip_address);
		printf("--------------------------------------------------\n");
    }
    return 0;
}
