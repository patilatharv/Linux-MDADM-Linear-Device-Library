#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "mdadm.h"
#include "jbod.h"


int mounted = 0;

uint32_t encode_op(int cmd, int disk_num, int block_num) {
  uint32_t op = 0;
  op |= cmd << 26;
  op |= disk_num << 22;
  op |= block_num;
  return op;
}

int mdadm_mount(void) {
  if (mounted == 1) 
  {
    return -1;
  }
  else 
  {
    uint32_t op = encode_op(JBOD_MOUNT, 0, 0);
    int rc = jbod_client_operation(op, NULL);
    if (rc == 0)
    {
      mounted = 1;
      return 1;
    }
  }
  mounted = 0;
  return -1;
}

int mdadm_unmount(void) {
  if (mounted == 0)
  {
    return -1;
  }
  else
  {
    uint32_t op = encode_op(JBOD_UNMOUNT, 0, 0);
    int rc = jbod_client_operation(op, NULL);
    if (rc == 0)
    {
      mounted = 0;
      return 1;
    }
  }
  mounted = 1;
  return -1;
}

void translate_address(uint32_t *addr, int *diskNum, int *blockNum, int *offset){
  *diskNum = *addr/65536;
  int offsetDisk = *addr%65536;
  *blockNum = offsetDisk/256;
  *offset = offsetDisk%256;
}

int min(int num1, int num2)
{
    return (num1 > num2) ? num2 : num1;
}

int mdadm_read(uint32_t addr, uint32_t len, uint8_t *buf) {
  if (mounted == 0)
  {
    return -1;
  }

  if (addr+len > 1048576)
  {
    return -1;
  }
  if (len > 1042)
  {
    return -1;
  } 
  if (len != 0 && buf == NULL)
  {
    return -1;
  }
  if (len == 0 && buf == NULL)
  {
    return 0;
  }

  int num_read = 0;
  int num_bytes_to_read_from_block;
  int disk_num;
  int block_num;
  int offset;
  uint8_t mybuf[256];

  int tempLen = len;
  while(num_read < tempLen) 
  {
    translate_address(&addr, &disk_num, &block_num, &offset);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_DISK, disk_num, block_num), NULL);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_BLOCK, disk_num, block_num), NULL);

    int cl = cache_lookup(disk_num, block_num, mybuf);

    if (cl != 1)
    {
      jbod_client_operation(encode_op(JBOD_READ_BLOCK, disk_num, block_num), mybuf);
      cache_insert(disk_num, block_num, mybuf);
    }

    num_bytes_to_read_from_block = min(len, min(JBOD_BLOCK_SIZE, JBOD_BLOCK_SIZE - offset));
    memcpy(buf + num_read, mybuf + offset, num_bytes_to_read_from_block);
  
    num_read += num_bytes_to_read_from_block; 
    len -= num_bytes_to_read_from_block; 
    addr += num_bytes_to_read_from_block; 
  
  }

  return num_read;
}

int mdadm_write(uint32_t addr, uint32_t len, const uint8_t *buf) {
  if (mounted == 0)
  {
    return -1;
  }

  if (addr+len > 1048576)
  {
    return -1;
  }
  if (len > 1042)
  {
    return -1;
  } 
  if (len != 0 && buf == NULL)
  {
    return -1;
  }
  if (len == 0 && buf == NULL)
  {
    return 0;
  }

  int num_bytes_to_write_from_buf;
  int num_write = 0;
  int disk_num;
  int block_num;
  int offset;
  
  int tempLen = len;
  while(num_write < tempLen)
  {
    translate_address(&addr, &disk_num, &block_num, &offset);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_DISK, disk_num, block_num), NULL);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_BLOCK, disk_num, block_num), NULL);

    uint8_t mybuf[256];
    int cl = cache_lookup(disk_num, block_num, mybuf);

    if (cl != 1)
    {
      jbod_client_operation(encode_op(JBOD_READ_BLOCK, disk_num, block_num), mybuf);
    }
    
    translate_address(&addr, &disk_num, &block_num, &offset);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_DISK, disk_num, block_num), NULL);
    jbod_client_operation(encode_op(JBOD_SEEK_TO_BLOCK, disk_num, block_num), NULL);

    num_bytes_to_write_from_buf = min(len, min(JBOD_BLOCK_SIZE, JBOD_BLOCK_SIZE - offset));
    memcpy(mybuf + offset, buf + num_write, num_bytes_to_write_from_buf);
    jbod_client_operation(encode_op(JBOD_WRITE_BLOCK, disk_num, block_num), mybuf);

    if (cl != 1)
    {
      cache_insert(disk_num, block_num, mybuf);
    }  
    else
    {
      cache_update(disk_num, block_num, mybuf);
    }

    num_write += num_bytes_to_write_from_buf;
    len -= num_bytes_to_write_from_buf;
    addr += num_bytes_to_write_from_buf;
  }

  return num_write;

}
