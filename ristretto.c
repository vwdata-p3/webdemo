// -- scalar.c --


const group_scalar group_scalar_zero  = {{0}};
const group_scalar group_scalar_one   = {{1}};

static const crypto_uint32 m[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

static const crypto_uint32 mu[33] = {0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED, 0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21, 
                                     0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F};

static crypto_uint32 lt(crypto_uint32 a,crypto_uint32 b) /* 16-bit inputs */
{
  unsigned int x = a;
  x -= (unsigned int) b; /* 0..65535: no; 4294901761..4294967295: yes */
  x >>= 31; /* 0: no; 1: yes */
  return x;
}

/* Reduce coefficients of r before calling reduce_add_sub */
static void reduce_add_sub(group_scalar *r)
{
  crypto_uint32 pb = 0;
  crypto_uint32 b;
  crypto_uint32 mask;
  int i;
  unsigned char t[32];

  for(i=0;i<32;i++) 
  {
    pb += m[i];
    b = lt(r->v[i],pb);
    t[i] = r->v[i]-pb+(b<<8);
    pb = b;
  }
  mask = b - 1;
  for(i=0;i<32;i++) 
    r->v[i] ^= mask & (r->v[i] ^ t[i]);
}

/* Reduce coefficients of x before calling barrett_reduce */
static void barrett_reduce(group_scalar *r, const crypto_uint32 x[64])
{
  /* See HAC, Alg. 14.42 */
  int i,j;
  crypto_uint32 q2[66];
  crypto_uint32 *q3 = q2 + 33;
  crypto_uint32 r1[33];
  crypto_uint32 r2[33];
  crypto_uint32 carry;
  crypto_uint32 pb = 0;
  crypto_uint32 b;

  for (i = 0;i < 66;++i) q2[i] = 0;
  for (i = 0;i < 33;++i) r2[i] = 0;

  for(i=0;i<33;i++)
    for(j=0;j<33;j++)
      if(i+j >= 31) q2[i+j] += mu[i]*x[j+31];
  carry = q2[31] >> 8;
  q2[32] += carry;
  carry = q2[32] >> 8;
  q2[33] += carry;

  for(i=0;i<33;i++)r1[i] = x[i];
  for(i=0;i<32;i++)
    for(j=0;j<33;j++)
      if(i+j < 33) r2[i+j] += m[i]*q3[j];

  for(i=0;i<32;i++)
  {
    carry = r2[i] >> 8;
    r2[i+1] += carry;
    r2[i] &= 0xff;
  }

  for(i=0;i<32;i++) 
  {
    pb += r2[i];
    b = lt(r1[i],pb);
    r->v[i] = r1[i]-pb+(b<<8);
    pb = b;
  }

  /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
   * If so: Handle  it here!
   */

  reduce_add_sub(r);
  reduce_add_sub(r);
}

int  group_scalar_unpack(group_scalar *r, const unsigned char x[GROUP_SCALAR_PACKEDBYTES])
{
  int i;
  for(i=0;i<32;i++)
    r->v[i] = x[i];
  r->v[31] &= 0x1f;
  reduce_add_sub(r);
  return 0;
}

void group_scalar_pack(unsigned char r[GROUP_SCALAR_PACKEDBYTES], const group_scalar *x)
{
  int i;
  for(i=0;i<32;i++)
    r[i] = x->v[i];
}

void group_scalar_setzero(group_scalar *r)
{
  int i;
  for(i=0;i<32;i++)
    r->v[i] = 0;
}

void group_scalar_setone(group_scalar *r)
{
  int i;
  r->v[0] = 1;
  for(i=1;i<32;i++)
    r->v[i] = 0;
}

/* Removed to avoid dependency on platform specific randombytes
void group_scalar_setrandom(group_scalar *r)
{
  unsigned char t[64];
  crypto_uint32 s[64];
  int i;
  randombytes(t,64);
  for(i=0;i<64;i++)
    s[i] = t[i];
  barrett_reduce(r,s);
}
*/

void group_scalar_add(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
  int i, carry;
  for(i=0;i<32;i++) r->v[i] = x->v[i] + y->v[i];
  for(i=0;i<31;i++)
  {
    carry = r->v[i] >> 8;
    r->v[i+1] += carry;
    r->v[i] &= 0xff;
  }
  reduce_add_sub(r);
}

void group_scalar_sub(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
  crypto_uint32 b = 0;
  crypto_uint32 t;
  int i;
  group_scalar d;

  for(i=0;i<32;i++)
  {
    t = m[i] - y->v[i] - b;
    d.v[i] = t & 255;
    b = (t >> 8) & 1;
  }
  group_scalar_add(r,x,&d);
}

void group_scalar_negate(group_scalar *r, const group_scalar *x)
{
  group_scalar t;
  group_scalar_setzero(&t);
  group_scalar_sub(r,&t,x);
}

void group_scalar_mul(group_scalar *r, const group_scalar *x, const group_scalar *y)
{
  int i,j,carry;
  crypto_uint32 t[64];
  for(i=0;i<64;i++)t[i] = 0;

  for(i=0;i<32;i++)
    for(j=0;j<32;j++)
      t[i+j] += x->v[i] * y->v[j];

  /* Reduce coefficients */
  for(i=0;i<63;i++)
  {
    carry = t[i] >> 8;
    t[i+1] += carry;
    t[i] &= 0xff;
  }

  barrett_reduce(r, t);
}

void group_scalar_square(group_scalar *r, const group_scalar *x)
{
  group_scalar_mul(r,x,x);
}

void group_scalar_invert(group_scalar *r, const group_scalar *x)
{
  group_scalar t0, t1, t2, t3, t4, t5;
  int i;

  group_scalar_square(&t1, x);
  group_scalar_mul(&t2, x, &t1);
  group_scalar_mul(&t0, &t1, &t2);
  group_scalar_square(&t1, &t0);
  group_scalar_square(&t3, &t1);
  group_scalar_mul(&t1, &t2, &t3);
  group_scalar_square(&t2, &t1);
  group_scalar_mul(&t3, &t0, &t2);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t1, &t2, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_square(&t3, &t0);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t3, &t1, &t0);
  group_scalar_mul(&t0, &t2, &t3);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t1, &t2);
  group_scalar_square(&t3, &t1);
  group_scalar_square(&t4, &t3);
  group_scalar_mul(&t3, &t1, &t4);
  group_scalar_mul(&t1, &t0, &t3);
  group_scalar_mul(&t0, &t2, &t1);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t1, &t2);
  group_scalar_square(&t3, &t1);
  group_scalar_mul(&t1, &t0, &t3);
  group_scalar_square(&t0, &t1);
  group_scalar_square(&t3, &t0);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_square(&t1, &t0);
  group_scalar_mul(&t0, &t2, &t1);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_square(&t3, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t3, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t3, &t0);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t1, &t2, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t4, &t2, &t0);
  group_scalar_square(&t0, &t4);
  group_scalar_square(&t4, &t0);
  group_scalar_mul(&t0, &t1, &t4);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t3, &t1, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t4, &t0);
  group_scalar_mul(&t0, &t3, &t4);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t2, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_mul(&t0, &t2, &t1);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t1, &t2);
  group_scalar_square(&t3, &t1);
  group_scalar_mul(&t1, &t0, &t3);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_square(&t1, &t0);
  group_scalar_square(&t2, &t1);
  group_scalar_mul(&t1, &t0, &t2);
  group_scalar_mul(&t2, &t3, &t1);
  group_scalar_mul(&t1, &t0, &t2);
  group_scalar_mul(&t0, &t2, &t1);
  group_scalar_square(&t2, &t0);
  group_scalar_mul(&t3, &t0, &t2);
  group_scalar_square(&t2, &t3);
  group_scalar_mul(&t3, &t1, &t2);
  group_scalar_mul(&t1, &t0, &t3);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t4, &t2, &t0);
  group_scalar_square(&t0, &t4);
  group_scalar_square(&t4, &t0);
  group_scalar_square(&t5, &t4);
  group_scalar_square(&t4, &t5);
  group_scalar_square(&t5, &t4);
  group_scalar_square(&t4, &t5);
  group_scalar_mul(&t5, &t0, &t4);
  group_scalar_mul(&t0, &t2, &t5);
  group_scalar_mul(&t2, &t3, &t0);
  group_scalar_mul(&t0, &t1, &t2);
  group_scalar_square(&t1, &t0);
  group_scalar_mul(&t3, &t0, &t1);
  group_scalar_square(&t1, &t3);
  group_scalar_mul(&t4, &t0, &t1);
  group_scalar_square(&t1, &t4);
  group_scalar_square(&t4, &t1);
  group_scalar_square(&t1, &t4);
  group_scalar_mul(&t4, &t3, &t1);
  group_scalar_mul(&t1, &t2, &t4);
  group_scalar_square(&t2, &t1);
  group_scalar_square(&t3, &t2);
  group_scalar_square(&t4, &t3);
  group_scalar_mul(&t3, &t2, &t4);
  group_scalar_mul(&t2, &t1, &t3);
  group_scalar_mul(&t3, &t0, &t2);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t2, &t0);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t2, &t1, &t0);
  group_scalar_mul(&t0, &t3, &t2);
  group_scalar_square(&t1, &t0);
  group_scalar_square(&t3, &t1);
  group_scalar_mul(&t4, &t1, &t3);
  group_scalar_square(&t3, &t4);
  group_scalar_square(&t4, &t3);
  group_scalar_mul(&t3, &t1, &t4);
  group_scalar_mul(&t1, &t2, &t3);
  group_scalar_square(&t2, &t1);
  group_scalar_square(&t3, &t2);
  group_scalar_mul(&t2, &t0, &t3);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t3, &t1, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t1, &t2, &t0);
  group_scalar_mul(&t0, &t3, &t1);
  group_scalar_square(&t2, &t0);
  group_scalar_square(&t3, &t2);
  group_scalar_square(&t2, &t3);
  group_scalar_square(&t3, &t2);
  group_scalar_mul(&t2, &t1, &t3);
  group_scalar_mul(&t1, &t0, &t2);
  group_scalar_square(&t0, &t1);
  group_scalar_square(&t3, &t0);
  group_scalar_square(&t4, &t3);
  group_scalar_mul(&t3, &t0, &t4);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t2, &t0);
  group_scalar_mul(&t0, &t1, &t2);
  group_scalar_square(&t1, &t0);
  group_scalar_mul(&t2, &t3, &t1);
  group_scalar_mul(&t1, &t0, &t2);
  group_scalar_square(&t0, &t1);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t2, &t0);
  group_scalar_mul(&t0, &t1, &t2);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_square(&t2, &t1);
  group_scalar_mul(&t3, &t0, &t2);
  group_scalar_mul(&t0, &t1, &t3);
  group_scalar_square(&t1, &t0);
  group_scalar_square(&t2, &t1);
  group_scalar_square(&t4, &t2);
  group_scalar_mul(&t2, &t1, &t4);
  group_scalar_square(&t4, &t2);
  group_scalar_square(&t2, &t4);
  group_scalar_square(&t4, &t2);
  group_scalar_mul(&t2, &t1, &t4);
  group_scalar_mul(&t1, &t3, &t2);
  group_scalar_square(&t2, &t1);
  group_scalar_square(&t3, &t2);
  group_scalar_mul(&t2, &t1, &t3);
  group_scalar_square(&t3, &t2);
  group_scalar_square(&t2, &t3);
  group_scalar_mul(&t3, &t1, &t2);
  group_scalar_mul(&t2, &t0, &t3);
  group_scalar_square(&t0, &t2);
  group_scalar_mul(&t3, &t2, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_square(&t4, &t0);
  group_scalar_mul(&t0, &t3, &t4);
  group_scalar_mul(&t3, &t1, &t0);
  group_scalar_square(&t0, &t3);
  group_scalar_mul(&t1, &t3, &t0);
  group_scalar_mul(&t0, &t2, &t1);
  for(i = 0; i < 126; i++)
    group_scalar_square(&t0, &t0);
  group_scalar_mul(r, &t3, &t0);
}

int  group_scalar_isone(const group_scalar *x)
{
  unsigned long long r;
  int i;
  r = 1-x->v[0];
  for(i=1;i<32;i++)
    r |= x->v[i];
  return 1-((-r)>>63);
}

int  group_scalar_iszero(const group_scalar *x)
{
  unsigned long long r=0;
  int i;
  for(i=0;i<32;i++)
    r |= x->v[i];
  return 1-((-r)>>63);
}

int  group_scalar_equals(const group_scalar *x,  const group_scalar *y)
{
  unsigned long long r=0;
  int i;
  for(i=0;i<32;i++)
    r |= (x->v[i] ^ y->v[i]);
  return 1-((-r)>>63);
}


// Additional functions, not required by API
int scalar_tstbit(const group_scalar *x, const unsigned int pos)
{
  return (x->v[pos >> 3] & (1ULL << (pos & 0x7))) >> (pos & 0x7);
}

int  scalar_bitlen(const group_scalar *x)
{
  int i;
  unsigned long long mask;
  int ctr = 256;
  int found = 0;
  int t;
  for(i=31;i>=0;i--)
  {
    for(mask = (1 << 7);mask>0;mask>>=1)
    {
      found = found || (mask & x->v[i]);
      t = ctr - 1;
      ctr = (found * ctr)^((1-found)*t);
    }
  }
  return ctr;
}

void scalar_window3(signed char r[85], const group_scalar *s)
{
  char carry;
  int i;
  for(i=0;i<10;i++)
  {
    r[8*i+0]  =  s->v[3*i+0]       & 7;
    r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
    r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
    r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
    r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
    r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;
    r[8*i+5]  = (s->v[3*i+1] >> 7) & 7;
    r[8*i+5] ^= (s->v[3*i+2] << 1) & 7;
    r[8*i+6]  = (s->v[3*i+2] >> 2) & 7;
    r[8*i+7]  = (s->v[3*i+2] >> 5) & 7;
  }
  r[8*i+0]  =  s->v[3*i+0]       & 7;
  r[8*i+1]  = (s->v[3*i+0] >> 3) & 7;
  r[8*i+2]  = (s->v[3*i+0] >> 6) & 7;
  r[8*i+2] ^= (s->v[3*i+1] << 2) & 7;
  r[8*i+3]  = (s->v[3*i+1] >> 1) & 7;
  r[8*i+4]  = (s->v[3*i+1] >> 4) & 7;

  /* Making it signed */
  carry = 0;
  for(i=0;i<84;i++)
  {
    r[i] += carry;
    r[i+1] += r[i] >> 3;
    r[i] &= 7;
    carry = r[i] >> 2;
    r[i] -= carry<<3;
  }
  r[84] += carry;
}

void scalar_window5(signed char r[51], const group_scalar *s) 
{
  char carry;
  int i;
  for(i=0;i<6;i++)
  {
    r[8*i+0]  =  s->v[5*i+0] & 31;
    r[8*i+1]  = (s->v[5*i+0] >> 5) & 31;
    r[8*i+1] ^= (s->v[5*i+1] << 3) & 31;
    r[8*i+2]  = (s->v[5*i+1] >> 2) & 31;
    r[8*i+3]  = (s->v[5*i+1] >> 7) & 31;
    r[8*i+3] ^= (s->v[5*i+2] << 1) & 31;
    r[8*i+4]  = (s->v[5*i+2] >> 4) & 31;
    r[8*i+4] ^= (s->v[5*i+3] << 4) & 31;
    r[8*i+5]  = (s->v[5*i+3] >> 1) & 31;
    r[8*i+6]  = (s->v[5*i+3] >> 6) & 31;
    r[8*i+6] ^= (s->v[5*i+4] << 2) & 31;
    r[8*i+7]  = (s->v[5*i+4] >> 3) & 31;
  }
  r[8*i+0]  =  s->v[5*i+0] & 31;
  r[8*i+1]  = (s->v[5*i+0] >> 5) & 31;
  r[8*i+1] ^= (s->v[5*i+1] << 3) & 31;
  r[8*i+2]  = (s->v[5*i+1] >> 2) & 31;


  /* Making it signed */
  carry = 0;
  for(i=0;i<50;i++)
  {
    r[i] += carry;
    r[i+1] += r[i] >> 5;
    r[i] &= 31; 
    carry = r[i] >> 4;
    r[i] -= carry << 5;
  }
  r[50] += carry;
}

void scalar_slide(signed char r[256], const group_scalar *s, int swindowsize)
{
  int i,j,k,b,m=(1<<(swindowsize-1))-1, soplen=256;

  for(i=0;i<32;i++) 
  {
    r[8*i+0] =  s->v[i] & 1;
    r[8*i+1] = (s->v[i] >> 1) & 1;
    r[8*i+2] = (s->v[i] >> 2) & 1;
    r[8*i+3] = (s->v[i] >> 3) & 1;
    r[8*i+4] = (s->v[i] >> 4) & 1;
    r[8*i+5] = (s->v[i] >> 5) & 1;
    r[8*i+6] = (s->v[i] >> 6) & 1;
    r[8*i+7] = (s->v[i] >> 7) & 1;
  }

  /* Making it sliding window */
  for (j = 0;j < soplen;++j) 
  {
    if (r[j]) {
      for (b = 1;b < soplen - j && b <= 6;++b) {
        if (r[j] + (r[j + b] << b) <= m) 
        {
          r[j] += r[j + b] << b; r[j + b] = 0;
        } 
        else if (r[j] - (r[j + b] << b) >= -m) 
        {
          r[j] -= r[j + b] << b;
          for (k = j + b;k < soplen;++k) 
          {
            if (!r[k]) {
              r[k] = 1;
              break;
            }
            r[k] = 0;
          }
        } 
        else if (r[j + b])
          break;
      }
    }
  }
}
/*
void scalar_print(const group_scalar *x)
{
  int i;
  for(i=0;i<31;i++)
    printf("%d*2^(%d*8) + ",x->v[i],i);
  printf("%d*2^(%d*8)\n",x->v[i],i);
}
*/
void scalar_from64bytes(group_scalar *r, const unsigned char h[64])
{
  int i;
  crypto_uint32 t[64];
  for(i=0;i<64;i++) t[i] = h[i];
  barrett_reduce(r, t); 
}



// -- fe25519.c --

const fe25519 fe25519_zero = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const fe25519 fe25519_one = {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const fe25519 fe25519_two = {{2, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const fe25519 fe25519_sqrtm1 = {{-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482}};
const fe25519 fe25519_msqrtm1 = {{32595792, 7943725, -9377950, -3500415, -12389472, 272473, 25146209, 2005654, -326686, -11406482}};
const fe25519 fe25519_m1 = {{-1, 0, 0, 0, 0, 0, 0, 0, 0, 0}};


static crypto_uint32 fe25519_c_static_equal(crypto_uint32 a,crypto_uint32 b) /* 16-bit inputs */
{
  crypto_uint32 x = a ^ b; /* 0: yes; 1..65535: no */
  x -= 1; /* 4294967295: yes; 0..65534: no */
  x >>= 31; /* 1: yes; 0: no */
  return x;
}

static crypto_uint64 load_3(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  return result;
}

static crypto_uint64 load_4(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  result |= ((crypto_uint64) in[3]) << 24;
  return result;
}

/*
 * Ignores top bit of h.
 */
void fe25519_unpack(fe25519 *h,const unsigned char s[32])
{
  crypto_int64 h0 = load_4(s);
  crypto_int64 h1 = load_3(s + 4) << 6;
  crypto_int64 h2 = load_3(s + 7) << 5;
  crypto_int64 h3 = load_3(s + 10) << 3;
  crypto_int64 h4 = load_3(s + 13) << 2;
  crypto_int64 h5 = load_4(s + 16);
  crypto_int64 h6 = load_3(s + 20) << 7;
  crypto_int64 h7 = load_3(s + 23) << 5;
  crypto_int64 h8 = load_3(s + 26) << 4;
  crypto_int64 h9 = (load_3(s + 29) & 8388607) << 2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;
  
  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  
  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}


/*
 * Preconditions:
 *  |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 * 
 * Write p=2^255-19; q=floor(h/p).
 * Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).
 * 
 * Proof:
 *  Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
 *  Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.
 * 
 *  Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
 *  Then 0<y<1.
 * 
 *  Write r=h-pq.
 *  Have 0<=r<=p-1=2^255-20.
 *  Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.
 * 
 *  Write x=r+19(2^-255)r+y.
 *  Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.
 * 
 *  Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
 *  so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.
 */

void fe25519_pack(unsigned char s[32],const fe25519 *h)
{
  crypto_int32 h0 = h->v[0];
  crypto_int32 h1 = h->v[1];
  crypto_int32 h2 = h->v[2];
  crypto_int32 h3 = h->v[3];
  crypto_int32 h4 = h->v[4];
  crypto_int32 h5 = h->v[5];
  crypto_int32 h6 = h->v[6];
  crypto_int32 h7 = h->v[7];
  crypto_int32 h8 = h->v[8];
  crypto_int32 h9 = h->v[9];
  crypto_int32 q;
  crypto_int32 carry0;
  crypto_int32 carry1;
  crypto_int32 carry2;
  crypto_int32 carry3;
  crypto_int32 carry4;
  crypto_int32 carry5;
  crypto_int32 carry6;
  crypto_int32 carry7;
  crypto_int32 carry8;
  crypto_int32 carry9;
  
  q = (19 * h9 + (((crypto_int32) 1) << 24)) >> 25;
  q = (h0 + q) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;
  
  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
  h0 += 19 * q;
  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */
  
  carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
  carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
  carry9 = h9 >> 25;               h9 -= carry9 << 25;
  /* h10 = carry9 */
  
  /*
   *  Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
   *  Have h0+...+2^230 h9 between 0 and 2^255-1;
   *  evidently 2^255 h10-2^255 q = 0.
   *  Goal: Output h0+...+2^230 h9.
   */
  
  s[0] = h0 >> 0;
  s[1] = h0 >> 8;
  s[2] = h0 >> 16;
  s[3] = (h0 >> 24) | (h1 << 2);
  s[4] = h1 >> 6;
  s[5] = h1 >> 14;
  s[6] = (h1 >> 22) | (h2 << 3);
  s[7] = h2 >> 5;
  s[8] = h2 >> 13;
  s[9] = (h2 >> 21) | (h3 << 5);
  s[10] = h3 >> 3;
  s[11] = h3 >> 11;
  s[12] = (h3 >> 19) | (h4 << 6);
  s[13] = h4 >> 2;
  s[14] = h4 >> 10;
  s[15] = h4 >> 18;
  s[16] = h5 >> 0;
  s[17] = h5 >> 8;
  s[18] = h5 >> 16;
  s[19] = (h5 >> 24) | (h6 << 1);
  s[20] = h6 >> 7;
  s[21] = h6 >> 15;
  s[22] = (h6 >> 23) | (h7 << 3);
  s[23] = h7 >> 5;
  s[24] = h7 >> 13;
  s[25] = (h7 >> 21) | (h8 << 4);
  s[26] = h8 >> 4;
  s[27] = h8 >> 12;
  s[28] = (h8 >> 20) | (h9 << 6);
  s[29] = h9 >> 2;
  s[30] = h9 >> 10;
  s[31] = h9 >> 18;
}

/*
 * return 1 if f == 0
 * return 0 if f != 0
 * 
 * Preconditions:
 *   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */
static const unsigned char zero[32];

int fe25519_iszero(const fe25519 *f)
{
  int i,r=0;
  unsigned char s[32];
  fe25519_pack(s,f);
  for(i=0;i<32;i++)
    r |= (1-fe25519_c_static_equal(zero[i],s[i]));
  return 1-r;
}

int fe25519_isone(const fe25519 *x) 
{
  return fe25519_iseq(x, &fe25519_one);  
}  

/*
 * return 1 if f is in {1,3,5,...,q-2}
 * return 0 if f is in {0,2,4,...,q-1}
 * 
 * Preconditions:
 *   |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */

int fe25519_isnegative(const fe25519 *f)
{
  unsigned char s[32];
  fe25519_pack(s,f);
  return s[0] & 1;
}

int fe25519_iseq(const fe25519 *x, const fe25519 *y)
{
  fe25519 t;
  fe25519_sub(&t, x, y);
  return fe25519_iszero(&t);
}

int fe25519_iseq_vartime(const fe25519 *x, const fe25519 *y) {
  return fe25519_iseq(x, y);
}  

/*
 * Replace (f,g) with (g,g) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 * 
 * Preconditions: b in {0,1}.
 */

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b)
{
  int i;
  crypto_uint32 mask = b;
  mask = -mask;
  for(i=0;i<10;i++) r->v[i] ^= mask & (x->v[i] ^ r->v[i]);
}


/*
 * h = 1
 */

void fe25519_setone(fe25519 *h)
{
  h->v[0] = 1;
  h->v[1] = 0;
  h->v[2] = 0;
  h->v[3] = 0;
  h->v[4] = 0;
  h->v[5] = 0;
  h->v[6] = 0;
  h->v[7] = 0;
  h->v[8] = 0;
  h->v[9] = 0;
}

/*
 * h = 0
 */

void fe25519_setzero(fe25519 *h)
{
  h->v[0] = 0;
  h->v[1] = 0;
  h->v[2] = 0;
  h->v[3] = 0;
  h->v[4] = 0;
  h->v[5] = 0;
  h->v[6] = 0;
  h->v[7] = 0;
  h->v[8] = 0;
  h->v[9] = 0;
}


/*
 * h = -f
 * 
 * Preconditions:
 *   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 * 
 * Postconditions:
 *   |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 */

void fe25519_neg(fe25519 *h, const fe25519 *f)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 h0 = -f0;
  crypto_int32 h1 = -f1;
  crypto_int32 h2 = -f2;
  crypto_int32 h3 = -f3;
  crypto_int32 h4 = -f4;
  crypto_int32 h5 = -f5;
  crypto_int32 h6 = -f6;
  crypto_int32 h7 = -f7;
  crypto_int32 h8 = -f8;
  crypto_int32 h9 = -f9;
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}


unsigned char fe25519_getparity(const fe25519 *x) {
  return fe25519_isnegative(x);  
}  


/*
 * h = f + g
 * Can overlap h with f or g.
 * 
 * Preconditions:
 *   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 * 
 * Postconditions:
 *   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */

void fe25519_add(fe25519 *h,const fe25519 *f,const fe25519 *g)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 g0 = g->v[0];
  crypto_int32 g1 = g->v[1];
  crypto_int32 g2 = g->v[2];
  crypto_int32 g3 = g->v[3];
  crypto_int32 g4 = g->v[4];
  crypto_int32 g5 = g->v[5];
  crypto_int32 g6 = g->v[6];
  crypto_int32 g7 = g->v[7];
  crypto_int32 g8 = g->v[8];
  crypto_int32 g9 = g->v[9];
  crypto_int32 h0 = f0 + g0;
  crypto_int32 h1 = f1 + g1;
  crypto_int32 h2 = f2 + g2;
  crypto_int32 h3 = f3 + g3;
  crypto_int32 h4 = f4 + g4;
  crypto_int32 h5 = f5 + g5;
  crypto_int32 h6 = f6 + g6;
  crypto_int32 h7 = f7 + g7;
  crypto_int32 h8 = f8 + g8;
  crypto_int32 h9 = f9 + g9;
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}


void fe25519_double(fe25519 *r, const fe25519 *x) {
  fe25519_add(r, x, x);  
}

void fe25519_triple(fe25519 *r, const fe25519 *x) {
  fe25519_add(r, x, x);
  fe25519_add(r, r, x);
}

/*
 * h = f - g
 * Can overlap h with f or g.
 * 
 * Preconditions:
 *   |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 *   |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
 * 
 * Postconditions:
 *   |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 */

void fe25519_sub(fe25519 *h,const fe25519 *f,const fe25519 *g)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 g0 = g->v[0];
  crypto_int32 g1 = g->v[1];
  crypto_int32 g2 = g->v[2];
  crypto_int32 g3 = g->v[3];
  crypto_int32 g4 = g->v[4];
  crypto_int32 g5 = g->v[5];
  crypto_int32 g6 = g->v[6];
  crypto_int32 g7 = g->v[7];
  crypto_int32 g8 = g->v[8];
  crypto_int32 g9 = g->v[9];
  crypto_int32 h0 = f0 - g0;
  crypto_int32 h1 = f1 - g1;
  crypto_int32 h2 = f2 - g2;
  crypto_int32 h3 = f3 - g3;
  crypto_int32 h4 = f4 - g4;
  crypto_int32 h5 = f5 - g5;
  crypto_int32 h6 = f6 - g6;
  crypto_int32 h7 = f7 - g7;
  crypto_int32 h8 = f8 - g8;
  crypto_int32 h9 = f9 - g9;
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}


/*
 * h = f * g
 * Can overlap h with f or g.
 * 
 * Preconditions:
 *   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 *   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 * 
 * Postconditions:
 *   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 */

/*
 * Notes on implementation strategy:
 * 
 * Using schoolbook multiplication.
 * Karatsuba would save a little in some cost models.
 * 
 * Most multiplications by 2 and 19 are 32-bit precomputations;
 * cheaper than 64-bit postcomputations.
 * 
 * There is one remaining multiplication by 19 in the carry chain;
 * one *19 precomputation can be merged into this,
 * but the resulting data flow is considerably less clean.
 * 
 * There are 12 carries below.
 * 10 of them are 2-way parallelizable and vectorizable.
 * Can get away with 11 carries, but then data flow is much deeper.
 * 
 * With tighter constraints on inputs can squeeze carries into int32.
 */

void fe25519_mul(fe25519 *h,const fe25519 *f,const fe25519 *g)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 g0 = g->v[0];
  crypto_int32 g1 = g->v[1];
  crypto_int32 g2 = g->v[2];
  crypto_int32 g3 = g->v[3];
  crypto_int32 g4 = g->v[4];
  crypto_int32 g5 = g->v[5];
  crypto_int32 g6 = g->v[6];
  crypto_int32 g7 = g->v[7];
  crypto_int32 g8 = g->v[8];
  crypto_int32 g9 = g->v[9];
  crypto_int32 g1_19 = 19 * g1; /* 1.959375*2^29 */
  crypto_int32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
  crypto_int32 g3_19 = 19 * g3;
  crypto_int32 g4_19 = 19 * g4;
  crypto_int32 g5_19 = 19 * g5;
  crypto_int32 g6_19 = 19 * g6;
  crypto_int32 g7_19 = 19 * g7;
  crypto_int32 g8_19 = 19 * g8;
  crypto_int32 g9_19 = 19 * g9;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f9_2 = 2 * f9;
  crypto_int64 f0g0    = f0   * (crypto_int64) g0;
  crypto_int64 f0g1    = f0   * (crypto_int64) g1;
  crypto_int64 f0g2    = f0   * (crypto_int64) g2;
  crypto_int64 f0g3    = f0   * (crypto_int64) g3;
  crypto_int64 f0g4    = f0   * (crypto_int64) g4;
  crypto_int64 f0g5    = f0   * (crypto_int64) g5;
  crypto_int64 f0g6    = f0   * (crypto_int64) g6;
  crypto_int64 f0g7    = f0   * (crypto_int64) g7;
  crypto_int64 f0g8    = f0   * (crypto_int64) g8;
  crypto_int64 f0g9    = f0   * (crypto_int64) g9;
  crypto_int64 f1g0    = f1   * (crypto_int64) g0;
  crypto_int64 f1g1_2  = f1_2 * (crypto_int64) g1;
  crypto_int64 f1g2    = f1   * (crypto_int64) g2;
  crypto_int64 f1g3_2  = f1_2 * (crypto_int64) g3;
  crypto_int64 f1g4    = f1   * (crypto_int64) g4;
  crypto_int64 f1g5_2  = f1_2 * (crypto_int64) g5;
  crypto_int64 f1g6    = f1   * (crypto_int64) g6;
  crypto_int64 f1g7_2  = f1_2 * (crypto_int64) g7;
  crypto_int64 f1g8    = f1   * (crypto_int64) g8;
  crypto_int64 f1g9_38 = f1_2 * (crypto_int64) g9_19;
  crypto_int64 f2g0    = f2   * (crypto_int64) g0;
  crypto_int64 f2g1    = f2   * (crypto_int64) g1;
  crypto_int64 f2g2    = f2   * (crypto_int64) g2;
  crypto_int64 f2g3    = f2   * (crypto_int64) g3;
  crypto_int64 f2g4    = f2   * (crypto_int64) g4;
  crypto_int64 f2g5    = f2   * (crypto_int64) g5;
  crypto_int64 f2g6    = f2   * (crypto_int64) g6;
  crypto_int64 f2g7    = f2   * (crypto_int64) g7;
  crypto_int64 f2g8_19 = f2   * (crypto_int64) g8_19;
  crypto_int64 f2g9_19 = f2   * (crypto_int64) g9_19;
  crypto_int64 f3g0    = f3   * (crypto_int64) g0;
  crypto_int64 f3g1_2  = f3_2 * (crypto_int64) g1;
  crypto_int64 f3g2    = f3   * (crypto_int64) g2;
  crypto_int64 f3g3_2  = f3_2 * (crypto_int64) g3;
  crypto_int64 f3g4    = f3   * (crypto_int64) g4;
  crypto_int64 f3g5_2  = f3_2 * (crypto_int64) g5;
  crypto_int64 f3g6    = f3   * (crypto_int64) g6;
  crypto_int64 f3g7_38 = f3_2 * (crypto_int64) g7_19;
  crypto_int64 f3g8_19 = f3   * (crypto_int64) g8_19;
  crypto_int64 f3g9_38 = f3_2 * (crypto_int64) g9_19;
  crypto_int64 f4g0    = f4   * (crypto_int64) g0;
  crypto_int64 f4g1    = f4   * (crypto_int64) g1;
  crypto_int64 f4g2    = f4   * (crypto_int64) g2;
  crypto_int64 f4g3    = f4   * (crypto_int64) g3;
  crypto_int64 f4g4    = f4   * (crypto_int64) g4;
  crypto_int64 f4g5    = f4   * (crypto_int64) g5;
  crypto_int64 f4g6_19 = f4   * (crypto_int64) g6_19;
  crypto_int64 f4g7_19 = f4   * (crypto_int64) g7_19;
  crypto_int64 f4g8_19 = f4   * (crypto_int64) g8_19;
  crypto_int64 f4g9_19 = f4   * (crypto_int64) g9_19;
  crypto_int64 f5g0    = f5   * (crypto_int64) g0;
  crypto_int64 f5g1_2  = f5_2 * (crypto_int64) g1;
  crypto_int64 f5g2    = f5   * (crypto_int64) g2;
  crypto_int64 f5g3_2  = f5_2 * (crypto_int64) g3;
  crypto_int64 f5g4    = f5   * (crypto_int64) g4;
  crypto_int64 f5g5_38 = f5_2 * (crypto_int64) g5_19;
  crypto_int64 f5g6_19 = f5   * (crypto_int64) g6_19;
  crypto_int64 f5g7_38 = f5_2 * (crypto_int64) g7_19;
  crypto_int64 f5g8_19 = f5   * (crypto_int64) g8_19;
  crypto_int64 f5g9_38 = f5_2 * (crypto_int64) g9_19;
  crypto_int64 f6g0    = f6   * (crypto_int64) g0;
  crypto_int64 f6g1    = f6   * (crypto_int64) g1;
  crypto_int64 f6g2    = f6   * (crypto_int64) g2;
  crypto_int64 f6g3    = f6   * (crypto_int64) g3;
  crypto_int64 f6g4_19 = f6   * (crypto_int64) g4_19;
  crypto_int64 f6g5_19 = f6   * (crypto_int64) g5_19;
  crypto_int64 f6g6_19 = f6   * (crypto_int64) g6_19;
  crypto_int64 f6g7_19 = f6   * (crypto_int64) g7_19;
  crypto_int64 f6g8_19 = f6   * (crypto_int64) g8_19;
  crypto_int64 f6g9_19 = f6   * (crypto_int64) g9_19;
  crypto_int64 f7g0    = f7   * (crypto_int64) g0;
  crypto_int64 f7g1_2  = f7_2 * (crypto_int64) g1;
  crypto_int64 f7g2    = f7   * (crypto_int64) g2;
  crypto_int64 f7g3_38 = f7_2 * (crypto_int64) g3_19;
  crypto_int64 f7g4_19 = f7   * (crypto_int64) g4_19;
  crypto_int64 f7g5_38 = f7_2 * (crypto_int64) g5_19;
  crypto_int64 f7g6_19 = f7   * (crypto_int64) g6_19;
  crypto_int64 f7g7_38 = f7_2 * (crypto_int64) g7_19;
  crypto_int64 f7g8_19 = f7   * (crypto_int64) g8_19;
  crypto_int64 f7g9_38 = f7_2 * (crypto_int64) g9_19;
  crypto_int64 f8g0    = f8   * (crypto_int64) g0;
  crypto_int64 f8g1    = f8   * (crypto_int64) g1;
  crypto_int64 f8g2_19 = f8   * (crypto_int64) g2_19;
  crypto_int64 f8g3_19 = f8   * (crypto_int64) g3_19;
  crypto_int64 f8g4_19 = f8   * (crypto_int64) g4_19;
  crypto_int64 f8g5_19 = f8   * (crypto_int64) g5_19;
  crypto_int64 f8g6_19 = f8   * (crypto_int64) g6_19;
  crypto_int64 f8g7_19 = f8   * (crypto_int64) g7_19;
  crypto_int64 f8g8_19 = f8   * (crypto_int64) g8_19;
  crypto_int64 f8g9_19 = f8   * (crypto_int64) g9_19;
  crypto_int64 f9g0    = f9   * (crypto_int64) g0;
  crypto_int64 f9g1_38 = f9_2 * (crypto_int64) g1_19;
  crypto_int64 f9g2_19 = f9   * (crypto_int64) g2_19;
  crypto_int64 f9g3_38 = f9_2 * (crypto_int64) g3_19;
  crypto_int64 f9g4_19 = f9   * (crypto_int64) g4_19;
  crypto_int64 f9g5_38 = f9_2 * (crypto_int64) g5_19;
  crypto_int64 f9g6_19 = f9   * (crypto_int64) g6_19;
  crypto_int64 f9g7_38 = f9_2 * (crypto_int64) g7_19;
  crypto_int64 f9g8_19 = f9   * (crypto_int64) g8_19;
  crypto_int64 f9g9_38 = f9_2 * (crypto_int64) g9_19;
  crypto_int64 h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
  crypto_int64 h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
  crypto_int64 h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
  crypto_int64 h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
  crypto_int64 h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
  crypto_int64 h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
  crypto_int64 h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
  crypto_int64 h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
  crypto_int64 h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
  crypto_int64 h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;
  
  /*
   *  |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
   *    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
   *  |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
   *    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
   */
  
  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */
  
  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */
  
  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */
  
  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */
  
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */
  
  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */
  
  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */
  
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}

/*
 * h = f * f
 * Can overlap h with f.
 * 
 * Preconditions:
 *   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
 * 
 * Postconditions:
 *   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
 */
void fe25519_square(fe25519 *h,const fe25519 *f)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 f0_2 = 2 * f0;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f2_2 = 2 * f2;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f4_2 = 2 * f4;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f6_2 = 2 * f6;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
  crypto_int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
  crypto_int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
  crypto_int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
  crypto_int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
  crypto_int64 f0f0    = f0   * (crypto_int64) f0;
  crypto_int64 f0f1_2  = f0_2 * (crypto_int64) f1;
  crypto_int64 f0f2_2  = f0_2 * (crypto_int64) f2;
  crypto_int64 f0f3_2  = f0_2 * (crypto_int64) f3;
  crypto_int64 f0f4_2  = f0_2 * (crypto_int64) f4;
  crypto_int64 f0f5_2  = f0_2 * (crypto_int64) f5;
  crypto_int64 f0f6_2  = f0_2 * (crypto_int64) f6;
  crypto_int64 f0f7_2  = f0_2 * (crypto_int64) f7;
  crypto_int64 f0f8_2  = f0_2 * (crypto_int64) f8;
  crypto_int64 f0f9_2  = f0_2 * (crypto_int64) f9;
  crypto_int64 f1f1_2  = f1_2 * (crypto_int64) f1;
  crypto_int64 f1f2_2  = f1_2 * (crypto_int64) f2;
  crypto_int64 f1f3_4  = f1_2 * (crypto_int64) f3_2;
  crypto_int64 f1f4_2  = f1_2 * (crypto_int64) f4;
  crypto_int64 f1f5_4  = f1_2 * (crypto_int64) f5_2;
  crypto_int64 f1f6_2  = f1_2 * (crypto_int64) f6;
  crypto_int64 f1f7_4  = f1_2 * (crypto_int64) f7_2;
  crypto_int64 f1f8_2  = f1_2 * (crypto_int64) f8;
  crypto_int64 f1f9_76 = f1_2 * (crypto_int64) f9_38;
  crypto_int64 f2f2    = f2   * (crypto_int64) f2;
  crypto_int64 f2f3_2  = f2_2 * (crypto_int64) f3;
  crypto_int64 f2f4_2  = f2_2 * (crypto_int64) f4;
  crypto_int64 f2f5_2  = f2_2 * (crypto_int64) f5;
  crypto_int64 f2f6_2  = f2_2 * (crypto_int64) f6;
  crypto_int64 f2f7_2  = f2_2 * (crypto_int64) f7;
  crypto_int64 f2f8_38 = f2_2 * (crypto_int64) f8_19;
  crypto_int64 f2f9_38 = f2   * (crypto_int64) f9_38;
  crypto_int64 f3f3_2  = f3_2 * (crypto_int64) f3;
  crypto_int64 f3f4_2  = f3_2 * (crypto_int64) f4;
  crypto_int64 f3f5_4  = f3_2 * (crypto_int64) f5_2;
  crypto_int64 f3f6_2  = f3_2 * (crypto_int64) f6;
  crypto_int64 f3f7_76 = f3_2 * (crypto_int64) f7_38;
  crypto_int64 f3f8_38 = f3_2 * (crypto_int64) f8_19;
  crypto_int64 f3f9_76 = f3_2 * (crypto_int64) f9_38;
  crypto_int64 f4f4    = f4   * (crypto_int64) f4;
  crypto_int64 f4f5_2  = f4_2 * (crypto_int64) f5;
  crypto_int64 f4f6_38 = f4_2 * (crypto_int64) f6_19;
  crypto_int64 f4f7_38 = f4   * (crypto_int64) f7_38;
  crypto_int64 f4f8_38 = f4_2 * (crypto_int64) f8_19;
  crypto_int64 f4f9_38 = f4   * (crypto_int64) f9_38;
  crypto_int64 f5f5_38 = f5   * (crypto_int64) f5_38;
  crypto_int64 f5f6_38 = f5_2 * (crypto_int64) f6_19;
  crypto_int64 f5f7_76 = f5_2 * (crypto_int64) f7_38;
  crypto_int64 f5f8_38 = f5_2 * (crypto_int64) f8_19;
  crypto_int64 f5f9_76 = f5_2 * (crypto_int64) f9_38;
  crypto_int64 f6f6_19 = f6   * (crypto_int64) f6_19;
  crypto_int64 f6f7_38 = f6   * (crypto_int64) f7_38;
  crypto_int64 f6f8_38 = f6_2 * (crypto_int64) f8_19;
  crypto_int64 f6f9_38 = f6   * (crypto_int64) f9_38;
  crypto_int64 f7f7_38 = f7   * (crypto_int64) f7_38;
  crypto_int64 f7f8_38 = f7_2 * (crypto_int64) f8_19;
  crypto_int64 f7f9_76 = f7_2 * (crypto_int64) f9_38;
  crypto_int64 f8f8_19 = f8   * (crypto_int64) f8_19;
  crypto_int64 f8f9_38 = f8   * (crypto_int64) f9_38;
  crypto_int64 f9f9_38 = f9   * (crypto_int64) f9_38;
  crypto_int64 h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  crypto_int64 h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  crypto_int64 h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  crypto_int64 h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  crypto_int64 h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  crypto_int64 h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  crypto_int64 h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  crypto_int64 h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  crypto_int64 h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  crypto_int64 h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;
  
  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  
  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  
  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  
  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  
  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  
  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  
  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}


void fe25519_invert(fe25519 *out,const fe25519 *z)
{
  fe25519 t0;
  fe25519 t1;
  fe25519 t2;
  fe25519 t3;
  int i;
  
  /* qhasm: fe z1 */
  
  /* qhasm: fe z2 */
  
  /* qhasm: fe z8 */
  
  /* qhasm: fe z9 */
  
  /* qhasm: fe z11 */
  
  /* qhasm: fe z22 */
  
  /* qhasm: fe z_5_0 */
  
  /* qhasm: fe z_10_5 */
  
  /* qhasm: fe z_10_0 */
  
  /* qhasm: fe z_20_10 */
  
  /* qhasm: fe z_20_0 */
  
  /* qhasm: fe z_40_20 */
  
  /* qhasm: fe z_40_0 */
  
  /* qhasm: fe z_50_10 */
  
  /* qhasm: fe z_50_0 */
  
  /* qhasm: fe z_100_50 */
  
  /* qhasm: fe z_100_0 */
  
  /* qhasm: fe z_200_100 */
  
  /* qhasm: fe z_200_0 */
  
  /* qhasm: fe z_250_50 */
  
  /* qhasm: fe z_250_0 */
  
  /* qhasm: fe z_255_5 */
  
  /* qhasm: fe z_255_21 */
  
  /* qhasm: enter pow225521 */
  
  /* qhasm: z2 = z1^2^1 */
  /* asm 1: fe25519_square(>z2=fe#1,<z1=fe#11); for (i = 1;i < 1;++i) fe25519_square(>z2=fe#1,>z2=fe#1); */
  /* asm 2: fe25519_square(>z2=&t0,<z1=z); for (i = 1;i < 1;++i) fe25519_square(>z2=&t0,>z2=&t0); */
  fe25519_square(&t0,z); for (i = 1;i < 1;++i) fe25519_square(&t0,&t0);
  
  /* qhasm: z8 = z2^2^2 */
  /* asm 1: fe25519_square(>z8=fe#2,<z2=fe#1); for (i = 1;i < 2;++i) fe25519_square(>z8=fe#2,>z8=fe#2); */
  /* asm 2: fe25519_square(>z8=&t1,<z2=&t0); for (i = 1;i < 2;++i) fe25519_square(>z8=&t1,>z8=&t1); */
  fe25519_square(&t1,&t0); for (i = 1;i < 2;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z9 = z1*z8 */
  /* asm 1: fe25519_mul(>z9=fe#2,<z1=fe#11,<z8=fe#2); */
  /* asm 2: fe25519_mul(>z9=&t1,<z1=z,<z8=&t1); */
  fe25519_mul(&t1,z,&t1);
  
  /* qhasm: z11 = z2*z9 */
  /* asm 1: fe25519_mul(>z11=fe#1,<z2=fe#1,<z9=fe#2); */
  /* asm 2: fe25519_mul(>z11=&t0,<z2=&t0,<z9=&t1); */
  fe25519_mul(&t0,&t0,&t1);
  
  /* qhasm: z22 = z11^2^1 */
  /* asm 1: fe25519_square(>z22=fe#3,<z11=fe#1); for (i = 1;i < 1;++i) fe25519_square(>z22=fe#3,>z22=fe#3); */
  /* asm 2: fe25519_square(>z22=&t2,<z11=&t0); for (i = 1;i < 1;++i) fe25519_square(>z22=&t2,>z22=&t2); */
  fe25519_square(&t2,&t0); for (i = 1;i < 1;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_5_0 = z9*z22 */
  /* asm 1: fe25519_mul(>z_5_0=fe#2,<z9=fe#2,<z22=fe#3); */
  /* asm 2: fe25519_mul(>z_5_0=&t1,<z9=&t1,<z22=&t2); */
  fe25519_mul(&t1,&t1,&t2);
  
  /* qhasm: z_10_5 = z_5_0^2^5 */
  /* asm 1: fe25519_square(>z_10_5=fe#3,<z_5_0=fe#2); for (i = 1;i < 5;++i) fe25519_square(>z_10_5=fe#3,>z_10_5=fe#3); */
  /* asm 2: fe25519_square(>z_10_5=&t2,<z_5_0=&t1); for (i = 1;i < 5;++i) fe25519_square(>z_10_5=&t2,>z_10_5=&t2); */
  fe25519_square(&t2,&t1); for (i = 1;i < 5;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_10_0 = z_10_5*z_5_0 */
  /* asm 1: fe25519_mul(>z_10_0=fe#2,<z_10_5=fe#3,<z_5_0=fe#2); */
  /* asm 2: fe25519_mul(>z_10_0=&t1,<z_10_5=&t2,<z_5_0=&t1); */
  fe25519_mul(&t1,&t2,&t1);
  
  /* qhasm: z_20_10 = z_10_0^2^10 */
  /* asm 1: fe25519_square(>z_20_10=fe#3,<z_10_0=fe#2); for (i = 1;i < 10;++i) fe25519_square(>z_20_10=fe#3,>z_20_10=fe#3); */
  /* asm 2: fe25519_square(>z_20_10=&t2,<z_10_0=&t1); for (i = 1;i < 10;++i) fe25519_square(>z_20_10=&t2,>z_20_10=&t2); */
  fe25519_square(&t2,&t1); for (i = 1;i < 10;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_20_0 = z_20_10*z_10_0 */
  /* asm 1: fe25519_mul(>z_20_0=fe#3,<z_20_10=fe#3,<z_10_0=fe#2); */
  /* asm 2: fe25519_mul(>z_20_0=&t2,<z_20_10=&t2,<z_10_0=&t1); */
  fe25519_mul(&t2,&t2,&t1);
  
  /* qhasm: z_40_20 = z_20_0^2^20 */
  /* asm 1: fe25519_square(>z_40_20=fe#4,<z_20_0=fe#3); for (i = 1;i < 20;++i) fe25519_square(>z_40_20=fe#4,>z_40_20=fe#4); */
  /* asm 2: fe25519_square(>z_40_20=&t3,<z_20_0=&t2); for (i = 1;i < 20;++i) fe25519_square(>z_40_20=&t3,>z_40_20=&t3); */
  fe25519_square(&t3,&t2); for (i = 1;i < 20;++i) fe25519_square(&t3,&t3);
  
  /* qhasm: z_40_0 = z_40_20*z_20_0 */
  /* asm 1: fe25519_mul(>z_40_0=fe#3,<z_40_20=fe#4,<z_20_0=fe#3); */
  /* asm 2: fe25519_mul(>z_40_0=&t2,<z_40_20=&t3,<z_20_0=&t2); */
  fe25519_mul(&t2,&t3,&t2);
  
  /* qhasm: z_50_10 = z_40_0^2^10 */
  /* asm 1: fe25519_square(>z_50_10=fe#3,<z_40_0=fe#3); for (i = 1;i < 10;++i) fe25519_square(>z_50_10=fe#3,>z_50_10=fe#3); */
  /* asm 2: fe25519_square(>z_50_10=&t2,<z_40_0=&t2); for (i = 1;i < 10;++i) fe25519_square(>z_50_10=&t2,>z_50_10=&t2); */
  fe25519_square(&t2,&t2); for (i = 1;i < 10;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_50_0 = z_50_10*z_10_0 */
  /* asm 1: fe25519_mul(>z_50_0=fe#2,<z_50_10=fe#3,<z_10_0=fe#2); */
  /* asm 2: fe25519_mul(>z_50_0=&t1,<z_50_10=&t2,<z_10_0=&t1); */
  fe25519_mul(&t1,&t2,&t1);
  
  /* qhasm: z_100_50 = z_50_0^2^50 */
  /* asm 1: fe25519_square(>z_100_50=fe#3,<z_50_0=fe#2); for (i = 1;i < 50;++i) fe25519_square(>z_100_50=fe#3,>z_100_50=fe#3); */
  /* asm 2: fe25519_square(>z_100_50=&t2,<z_50_0=&t1); for (i = 1;i < 50;++i) fe25519_square(>z_100_50=&t2,>z_100_50=&t2); */
  fe25519_square(&t2,&t1); for (i = 1;i < 50;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_100_0 = z_100_50*z_50_0 */
  /* asm 1: fe25519_mul(>z_100_0=fe#3,<z_100_50=fe#3,<z_50_0=fe#2); */
  /* asm 2: fe25519_mul(>z_100_0=&t2,<z_100_50=&t2,<z_50_0=&t1); */
  fe25519_mul(&t2,&t2,&t1);
  
  /* qhasm: z_200_100 = z_100_0^2^100 */
  /* asm 1: fe25519_square(>z_200_100=fe#4,<z_100_0=fe#3); for (i = 1;i < 100;++i) fe25519_square(>z_200_100=fe#4,>z_200_100=fe#4); */
  /* asm 2: fe25519_square(>z_200_100=&t3,<z_100_0=&t2); for (i = 1;i < 100;++i) fe25519_square(>z_200_100=&t3,>z_200_100=&t3); */
  fe25519_square(&t3,&t2); for (i = 1;i < 100;++i) fe25519_square(&t3,&t3);
  
  /* qhasm: z_200_0 = z_200_100*z_100_0 */
  /* asm 1: fe25519_mul(>z_200_0=fe#3,<z_200_100=fe#4,<z_100_0=fe#3); */
  /* asm 2: fe25519_mul(>z_200_0=&t2,<z_200_100=&t3,<z_100_0=&t2); */
  fe25519_mul(&t2,&t3,&t2);
  
  /* qhasm: z_250_50 = z_200_0^2^50 */
  /* asm 1: fe25519_square(>z_250_50=fe#3,<z_200_0=fe#3); for (i = 1;i < 50;++i) fe25519_square(>z_250_50=fe#3,>z_250_50=fe#3); */
  /* asm 2: fe25519_square(>z_250_50=&t2,<z_200_0=&t2); for (i = 1;i < 50;++i) fe25519_square(>z_250_50=&t2,>z_250_50=&t2); */
  fe25519_square(&t2,&t2); for (i = 1;i < 50;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_250_0 = z_250_50*z_50_0 */
  /* asm 1: fe25519_mul(>z_250_0=fe#2,<z_250_50=fe#3,<z_50_0=fe#2); */
  /* asm 2: fe25519_mul(>z_250_0=&t1,<z_250_50=&t2,<z_50_0=&t1); */
  fe25519_mul(&t1,&t2,&t1);
  
  /* qhasm: z_255_5 = z_250_0^2^5 */
  /* asm 1: fe25519_square(>z_255_5=fe#2,<z_250_0=fe#2); for (i = 1;i < 5;++i) fe25519_square(>z_255_5=fe#2,>z_255_5=fe#2); */
  /* asm 2: fe25519_square(>z_255_5=&t1,<z_250_0=&t1); for (i = 1;i < 5;++i) fe25519_square(>z_255_5=&t1,>z_255_5=&t1); */
  fe25519_square(&t1,&t1); for (i = 1;i < 5;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_255_21 = z_255_5*z11 */
  /* asm 1: fe25519_mul(>z_255_21=fe#12,<z_255_5=fe#2,<z11=fe#1); */
  /* asm 2: fe25519_mul(>z_255_21=out,<z_255_5=&t1,<z11=&t0); */
  fe25519_mul(out,&t1,&t0);
  
  /* qhasm: return */
  
  return;
}


void fe25519_pow2523(fe25519 *out,const fe25519 *z)
{
  fe25519 t0;
  fe25519 t1;
  fe25519 t2;
  int i;
  
  /* qhasm: fe z1 */
  
  /* qhasm: fe z2 */
  
  /* qhasm: fe z8 */
  
  /* qhasm: fe z9 */
  
  /* qhasm: fe z11 */
  
  /* qhasm: fe z22 */
  
  /* qhasm: fe z_5_0 */
  
  /* qhasm: fe z_10_5 */
  
  /* qhasm: fe z_10_0 */
  
  /* qhasm: fe z_20_10 */
  
  /* qhasm: fe z_20_0 */
  
  /* qhasm: fe z_40_20 */
  
  /* qhasm: fe z_40_0 */
  
  /* qhasm: fe z_50_10 */
  
  /* qhasm: fe z_50_0 */
  
  /* qhasm: fe z_100_50 */
  
  /* qhasm: fe z_100_0 */
  
  /* qhasm: fe z_200_100 */
  
  /* qhasm: fe z_200_0 */
  
  /* qhasm: fe z_250_50 */
  
  /* qhasm: fe z_250_0 */
  
  /* qhasm: fe z_252_2 */
  
  /* qhasm: fe z_252_3 */
  
  /* qhasm: enter pow22523 */
  
  /* qhasm: z2 = z1^2^1 */
  /* asm 1: fe25519_square(>z2=fe#1,<z1=fe#11); for (i = 1;i < 1;++i) fe25519_square(>z2=fe#1,>z2=fe#1); */
  /* asm 2: fe25519_square(>z2=&t0,<z1=z); for (i = 1;i < 1;++i) fe25519_square(>z2=&t0,>z2=&t0); */
  fe25519_square(&t0,z); for (i = 1;i < 1;++i) fe25519_square(&t0,&t0);
  
  /* qhasm: z8 = z2^2^2 */
  /* asm 1: fe25519_square(>z8=fe#2,<z2=fe#1); for (i = 1;i < 2;++i) fe25519_square(>z8=fe#2,>z8=fe#2); */
  /* asm 2: fe25519_square(>z8=&t1,<z2=&t0); for (i = 1;i < 2;++i) fe25519_square(>z8=&t1,>z8=&t1); */
  fe25519_square(&t1,&t0); for (i = 1;i < 2;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z9 = z1*z8 */
  /* asm 1: fe25519_mul(>z9=fe#2,<z1=fe#11,<z8=fe#2); */
  /* asm 2: fe25519_mul(>z9=&t1,<z1=z,<z8=&t1); */
  fe25519_mul(&t1,z,&t1);
  
  /* qhasm: z11 = z2*z9 */
  /* asm 1: fe25519_mul(>z11=fe#1,<z2=fe#1,<z9=fe#2); */
  /* asm 2: fe25519_mul(>z11=&t0,<z2=&t0,<z9=&t1); */
  fe25519_mul(&t0,&t0,&t1);
  
  /* qhasm: z22 = z11^2^1 */
  /* asm 1: fe25519_square(>z22=fe#1,<z11=fe#1); for (i = 1;i < 1;++i) fe25519_square(>z22=fe#1,>z22=fe#1); */
  /* asm 2: fe25519_square(>z22=&t0,<z11=&t0); for (i = 1;i < 1;++i) fe25519_square(>z22=&t0,>z22=&t0); */
  fe25519_square(&t0,&t0); for (i = 1;i < 1;++i) fe25519_square(&t0,&t0);
  
  /* qhasm: z_5_0 = z9*z22 */
  /* asm 1: fe25519_mul(>z_5_0=fe#1,<z9=fe#2,<z22=fe#1); */
  /* asm 2: fe25519_mul(>z_5_0=&t0,<z9=&t1,<z22=&t0); */
  fe25519_mul(&t0,&t1,&t0);
  
  /* qhasm: z_10_5 = z_5_0^2^5 */
  /* asm 1: fe25519_square(>z_10_5=fe#2,<z_5_0=fe#1); for (i = 1;i < 5;++i) fe25519_square(>z_10_5=fe#2,>z_10_5=fe#2); */
  /* asm 2: fe25519_square(>z_10_5=&t1,<z_5_0=&t0); for (i = 1;i < 5;++i) fe25519_square(>z_10_5=&t1,>z_10_5=&t1); */
  fe25519_square(&t1,&t0); for (i = 1;i < 5;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_10_0 = z_10_5*z_5_0 */
  /* asm 1: fe25519_mul(>z_10_0=fe#1,<z_10_5=fe#2,<z_5_0=fe#1); */
  /* asm 2: fe25519_mul(>z_10_0=&t0,<z_10_5=&t1,<z_5_0=&t0); */
  fe25519_mul(&t0,&t1,&t0);
  
  /* qhasm: z_20_10 = z_10_0^2^10 */
  /* asm 1: fe25519_square(>z_20_10=fe#2,<z_10_0=fe#1); for (i = 1;i < 10;++i) fe25519_square(>z_20_10=fe#2,>z_20_10=fe#2); */
  /* asm 2: fe25519_square(>z_20_10=&t1,<z_10_0=&t0); for (i = 1;i < 10;++i) fe25519_square(>z_20_10=&t1,>z_20_10=&t1); */
  fe25519_square(&t1,&t0); for (i = 1;i < 10;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_20_0 = z_20_10*z_10_0 */
  /* asm 1: fe25519_mul(>z_20_0=fe#2,<z_20_10=fe#2,<z_10_0=fe#1); */
  /* asm 2: fe25519_mul(>z_20_0=&t1,<z_20_10=&t1,<z_10_0=&t0); */
  fe25519_mul(&t1,&t1,&t0);
  
  /* qhasm: z_40_20 = z_20_0^2^20 */
  /* asm 1: fe25519_square(>z_40_20=fe#3,<z_20_0=fe#2); for (i = 1;i < 20;++i) fe25519_square(>z_40_20=fe#3,>z_40_20=fe#3); */
  /* asm 2: fe25519_square(>z_40_20=&t2,<z_20_0=&t1); for (i = 1;i < 20;++i) fe25519_square(>z_40_20=&t2,>z_40_20=&t2); */
  fe25519_square(&t2,&t1); for (i = 1;i < 20;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_40_0 = z_40_20*z_20_0 */
  /* asm 1: fe25519_mul(>z_40_0=fe#2,<z_40_20=fe#3,<z_20_0=fe#2); */
  /* asm 2: fe25519_mul(>z_40_0=&t1,<z_40_20=&t2,<z_20_0=&t1); */
  fe25519_mul(&t1,&t2,&t1);
  
  /* qhasm: z_50_10 = z_40_0^2^10 */
  /* asm 1: fe25519_square(>z_50_10=fe#2,<z_40_0=fe#2); for (i = 1;i < 10;++i) fe25519_square(>z_50_10=fe#2,>z_50_10=fe#2); */
  /* asm 2: fe25519_square(>z_50_10=&t1,<z_40_0=&t1); for (i = 1;i < 10;++i) fe25519_square(>z_50_10=&t1,>z_50_10=&t1); */
  fe25519_square(&t1,&t1); for (i = 1;i < 10;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_50_0 = z_50_10*z_10_0 */
  /* asm 1: fe25519_mul(>z_50_0=fe#1,<z_50_10=fe#2,<z_10_0=fe#1); */
  /* asm 2: fe25519_mul(>z_50_0=&t0,<z_50_10=&t1,<z_10_0=&t0); */
  fe25519_mul(&t0,&t1,&t0);
  
  /* qhasm: z_100_50 = z_50_0^2^50 */
  /* asm 1: fe25519_square(>z_100_50=fe#2,<z_50_0=fe#1); for (i = 1;i < 50;++i) fe25519_square(>z_100_50=fe#2,>z_100_50=fe#2); */
  /* asm 2: fe25519_square(>z_100_50=&t1,<z_50_0=&t0); for (i = 1;i < 50;++i) fe25519_square(>z_100_50=&t1,>z_100_50=&t1); */
  fe25519_square(&t1,&t0); for (i = 1;i < 50;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_100_0 = z_100_50*z_50_0 */
  /* asm 1: fe25519_mul(>z_100_0=fe#2,<z_100_50=fe#2,<z_50_0=fe#1); */
  /* asm 2: fe25519_mul(>z_100_0=&t1,<z_100_50=&t1,<z_50_0=&t0); */
  fe25519_mul(&t1,&t1,&t0);
  
  /* qhasm: z_200_100 = z_100_0^2^100 */
  /* asm 1: fe25519_square(>z_200_100=fe#3,<z_100_0=fe#2); for (i = 1;i < 100;++i) fe25519_square(>z_200_100=fe#3,>z_200_100=fe#3); */
  /* asm 2: fe25519_square(>z_200_100=&t2,<z_100_0=&t1); for (i = 1;i < 100;++i) fe25519_square(>z_200_100=&t2,>z_200_100=&t2); */
  fe25519_square(&t2,&t1); for (i = 1;i < 100;++i) fe25519_square(&t2,&t2);
  
  /* qhasm: z_200_0 = z_200_100*z_100_0 */
  /* asm 1: fe25519_mul(>z_200_0=fe#2,<z_200_100=fe#3,<z_100_0=fe#2); */
  /* asm 2: fe25519_mul(>z_200_0=&t1,<z_200_100=&t2,<z_100_0=&t1); */
  fe25519_mul(&t1,&t2,&t1);
  
  /* qhasm: z_250_50 = z_200_0^2^50 */
  /* asm 1: fe25519_square(>z_250_50=fe#2,<z_200_0=fe#2); for (i = 1;i < 50;++i) fe25519_square(>z_250_50=fe#2,>z_250_50=fe#2); */
  /* asm 2: fe25519_square(>z_250_50=&t1,<z_200_0=&t1); for (i = 1;i < 50;++i) fe25519_square(>z_250_50=&t1,>z_250_50=&t1); */
  fe25519_square(&t1,&t1); for (i = 1;i < 50;++i) fe25519_square(&t1,&t1);
  
  /* qhasm: z_250_0 = z_250_50*z_50_0 */
  /* asm 1: fe25519_mul(>z_250_0=fe#1,<z_250_50=fe#2,<z_50_0=fe#1); */
  /* asm 2: fe25519_mul(>z_250_0=&t0,<z_250_50=&t1,<z_50_0=&t0); */
  fe25519_mul(&t0,&t1,&t0);
  
  /* qhasm: z_252_2 = z_250_0^2^2 */
  /* asm 1: fe25519_square(>z_252_2=fe#1,<z_250_0=fe#1); for (i = 1;i < 2;++i) fe25519_square(>z_252_2=fe#1,>z_252_2=fe#1); */
  /* asm 2: fe25519_square(>z_252_2=&t0,<z_250_0=&t0); for (i = 1;i < 2;++i) fe25519_square(>z_252_2=&t0,>z_252_2=&t0); */
  fe25519_square(&t0,&t0); for (i = 1;i < 2;++i) fe25519_square(&t0,&t0);
  
  /* qhasm: z_252_3 = z_252_2*z1 */
  /* asm 1: fe25519_mul(>z_252_3=fe#12,<z_252_2=fe#1,<z1=fe#11); */
  /* asm 2: fe25519_mul(>z_252_3=out,<z_252_2=&t0,<z1=z); */
  fe25519_mul(out,&t0,z);
  
  /* qhasm: return */
  
  
  return;
}

/*
h = 2 * f * f
Can overlap h with f.

Preconditions:
   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

Postconditions:
   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
*/

/*
See fe_mul.c for discussion of implementation strategy.
*/
void fe25519_square_double(fe25519 *h,const fe25519 *f)
{
  crypto_int32 f0 = f->v[0];
  crypto_int32 f1 = f->v[1];
  crypto_int32 f2 = f->v[2];
  crypto_int32 f3 = f->v[3];
  crypto_int32 f4 = f->v[4];
  crypto_int32 f5 = f->v[5];
  crypto_int32 f6 = f->v[6];
  crypto_int32 f7 = f->v[7];
  crypto_int32 f8 = f->v[8];
  crypto_int32 f9 = f->v[9];
  crypto_int32 f0_2 = 2 * f0;
  crypto_int32 f1_2 = 2 * f1;
  crypto_int32 f2_2 = 2 * f2;
  crypto_int32 f3_2 = 2 * f3;
  crypto_int32 f4_2 = 2 * f4;
  crypto_int32 f5_2 = 2 * f5;
  crypto_int32 f6_2 = 2 * f6;
  crypto_int32 f7_2 = 2 * f7;
  crypto_int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
  crypto_int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
  crypto_int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
  crypto_int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
  crypto_int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
  crypto_int64 f0f0    = f0   * (crypto_int64) f0;
  crypto_int64 f0f1_2  = f0_2 * (crypto_int64) f1;
  crypto_int64 f0f2_2  = f0_2 * (crypto_int64) f2;
  crypto_int64 f0f3_2  = f0_2 * (crypto_int64) f3;
  crypto_int64 f0f4_2  = f0_2 * (crypto_int64) f4;
  crypto_int64 f0f5_2  = f0_2 * (crypto_int64) f5;
  crypto_int64 f0f6_2  = f0_2 * (crypto_int64) f6;
  crypto_int64 f0f7_2  = f0_2 * (crypto_int64) f7;
  crypto_int64 f0f8_2  = f0_2 * (crypto_int64) f8;
  crypto_int64 f0f9_2  = f0_2 * (crypto_int64) f9;
  crypto_int64 f1f1_2  = f1_2 * (crypto_int64) f1;
  crypto_int64 f1f2_2  = f1_2 * (crypto_int64) f2;
  crypto_int64 f1f3_4  = f1_2 * (crypto_int64) f3_2;
  crypto_int64 f1f4_2  = f1_2 * (crypto_int64) f4;
  crypto_int64 f1f5_4  = f1_2 * (crypto_int64) f5_2;
  crypto_int64 f1f6_2  = f1_2 * (crypto_int64) f6;
  crypto_int64 f1f7_4  = f1_2 * (crypto_int64) f7_2;
  crypto_int64 f1f8_2  = f1_2 * (crypto_int64) f8;
  crypto_int64 f1f9_76 = f1_2 * (crypto_int64) f9_38;
  crypto_int64 f2f2    = f2   * (crypto_int64) f2;
  crypto_int64 f2f3_2  = f2_2 * (crypto_int64) f3;
  crypto_int64 f2f4_2  = f2_2 * (crypto_int64) f4;
  crypto_int64 f2f5_2  = f2_2 * (crypto_int64) f5;
  crypto_int64 f2f6_2  = f2_2 * (crypto_int64) f6;
  crypto_int64 f2f7_2  = f2_2 * (crypto_int64) f7;
  crypto_int64 f2f8_38 = f2_2 * (crypto_int64) f8_19;
  crypto_int64 f2f9_38 = f2   * (crypto_int64) f9_38;
  crypto_int64 f3f3_2  = f3_2 * (crypto_int64) f3;
  crypto_int64 f3f4_2  = f3_2 * (crypto_int64) f4;
  crypto_int64 f3f5_4  = f3_2 * (crypto_int64) f5_2;
  crypto_int64 f3f6_2  = f3_2 * (crypto_int64) f6;
  crypto_int64 f3f7_76 = f3_2 * (crypto_int64) f7_38;
  crypto_int64 f3f8_38 = f3_2 * (crypto_int64) f8_19;
  crypto_int64 f3f9_76 = f3_2 * (crypto_int64) f9_38;
  crypto_int64 f4f4    = f4   * (crypto_int64) f4;
  crypto_int64 f4f5_2  = f4_2 * (crypto_int64) f5;
  crypto_int64 f4f6_38 = f4_2 * (crypto_int64) f6_19;
  crypto_int64 f4f7_38 = f4   * (crypto_int64) f7_38;
  crypto_int64 f4f8_38 = f4_2 * (crypto_int64) f8_19;
  crypto_int64 f4f9_38 = f4   * (crypto_int64) f9_38;
  crypto_int64 f5f5_38 = f5   * (crypto_int64) f5_38;
  crypto_int64 f5f6_38 = f5_2 * (crypto_int64) f6_19;
  crypto_int64 f5f7_76 = f5_2 * (crypto_int64) f7_38;
  crypto_int64 f5f8_38 = f5_2 * (crypto_int64) f8_19;
  crypto_int64 f5f9_76 = f5_2 * (crypto_int64) f9_38;
  crypto_int64 f6f6_19 = f6   * (crypto_int64) f6_19;
  crypto_int64 f6f7_38 = f6   * (crypto_int64) f7_38;
  crypto_int64 f6f8_38 = f6_2 * (crypto_int64) f8_19;
  crypto_int64 f6f9_38 = f6   * (crypto_int64) f9_38;
  crypto_int64 f7f7_38 = f7   * (crypto_int64) f7_38;
  crypto_int64 f7f8_38 = f7_2 * (crypto_int64) f8_19;
  crypto_int64 f7f9_76 = f7_2 * (crypto_int64) f9_38;
  crypto_int64 f8f8_19 = f8   * (crypto_int64) f8_19;
  crypto_int64 f8f9_38 = f8   * (crypto_int64) f9_38;
  crypto_int64 f9f9_38 = f9   * (crypto_int64) f9_38;
  crypto_int64 h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  crypto_int64 h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  crypto_int64 h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  crypto_int64 h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  crypto_int64 h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  crypto_int64 h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  crypto_int64 h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  crypto_int64 h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  crypto_int64 h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  crypto_int64 h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  h0 += h0;
  h1 += h1;
  h2 += h2;
  h3 += h3;
  h4 += h4;
  h5 += h5;
  h6 += h6;
  h7 += h7;
  h8 += h8;
  h9 += h9;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

  carry1 = (h1 + (crypto_int64) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (crypto_int64) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

  carry2 = (h2 + (crypto_int64) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (crypto_int64) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

  carry3 = (h3 + (crypto_int64) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (crypto_int64) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry4 = (h4 + (crypto_int64) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (crypto_int64) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  carry9 = (h9 + (crypto_int64) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

  carry0 = (h0 + (crypto_int64) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

  h->v[0] = h0;
  h->v[1] = h1;
  h->v[2] = h2;
  h->v[3] = h3;
  h->v[4] = h4;
  h->v[5] = h5;
  h->v[6] = h6;
  h->v[7] = h7;
  h->v[8] = h8;
  h->v[9] = h9;
}

void fe25519_sqrt(fe25519 *r, const fe25519 *x)
{
  fe25519 t;
  fe25519_invsqrt(&t, x);
  fe25519_mul(r, &t, x);
}

void fe25519_invsqrt(fe25519 *r, const fe25519 *x)
{
  fe25519 den2, den3, den4, den6, chk, t;
  fe25519_square(&den2, x);
  fe25519_mul(&den3, &den2, x);
  
  fe25519_square(&den4, &den2);
  fe25519_mul(&den6, &den2, &den4);
  fe25519_mul(&t, &den6, x); // r is now x^7
  
  fe25519_pow2523(&t, &t);
  fe25519_mul(&t, &t, &den3);
  
  fe25519_square(&chk, &t);
  fe25519_mul(&chk, &chk, x);
  
  if(!fe25519_isone(&chk)) //XXX: Make constant time
    fe25519_mul(&t, &t, &fe25519_sqrtm1);
  
  *r = t;
}






// -- group.c --

/* 
 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 
 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
 */


static const fe25519 ge25519_ecd = {{-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116}};
static const fe25519 ge25519_ec2d = {{-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199}};
static const fe25519 ge25519_magic = {{-6111485, -4156064, 27798727, -12243468, 25904040, -120897, -20826367, 7060776, -6093568, 1986012}};
const group_ge group_ge_neutral = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                    {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                    {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}};

#define ge25519_p3 group_ge

typedef struct
{
  fe25519 x;
  fe25519 z;
  fe25519 y;
  fe25519 t;
} ge25519_p1p1;

typedef struct
{
  fe25519 x;
  fe25519 y;
  fe25519 z;
} ge25519_p2;

typedef struct
{
  fe25519 x;
  fe25519 y;
} ge25519_aff;


/* Multiples of the base point in affine representation */
static const ge25519_aff ge25519_base_multiples_affine[425] = {
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491}}, {{-26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886}}},
{{{4443662, -9940086, 9171065, 2666173, 2111033, 3401644, -31605108, 9275297, 13235616, 14331105}}, {{-17259575, -3036261, -30752308, 9118147, -27466691, -6152361, 19887205, -13089868, -13594061, 9012024}}},
{{{-466321, 9574389, 17880460, 13372178, 26021472, 14338106, -27837921, -1498113, 10627369, -6374799}}, {{16102612, 14291486, 6324312, 12269856, -25404496, 2531064, -11483344, -13274075, 18317031, 4824775}}},
{{{13236336, 11113969, -22484697, 826993, 6934139, 3481849, -18195395, 2674789, 28667135, 8451747}}, {{-30273214, 2807923, 33430503, -6860424, 20170913, 13988204, -10730816, 12331234, -25382567, -14728287}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{10847451, -37118, 24323953, -2358452, -5444838, 5164948, -15290756, 3590225, 33127799, -6485115}}, {{3652020, -2692481, 9593798, -1896201, -33169164, 9106320, -21527373, 7286230, 826967, 8866840}}},
{{{2685432, 9853787, 7244598, -6341127, 2448949, 2399377, 18188932, -10627300, 6454868, 9343512}}, {{23537662, 11193840, -8062193, -233411, -20862904, 11366009, 497437, 7230451, -14145540, -4040100}}},
{{{8940436, -931910, 2216655, -16607923, 25443172, -13796962, -12136885, 56339, -24611372, -4038275}}, {{24869380, 9507835, 27335926, 9455120, -8487096, 2134990, 18474949, -13554247, 20744060, -8308626}}},
{{{-8499418, -11518554, -27293188, 8899523, -6812474, -13019522, 19598982, -10538832, -24021982, 15154610}}, {{-33107332, -11643953, 466726, -12950430, -19904488, 16288633, -11930016, -3313828, 15602381, -15674716}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{3974155, 6194156, -19980758, -1354033, -18636516, -14845527, 21527748, -14519394, -33505405, 1567121}}, {{-2488026, -5936186, -13803653, 15954025, -26753975, -5723571, -29147976, 331359, -22048160, 16017020}}},
{{{13622663, 9590524, -12055628, -14601956, -30798357, 13798328, 24469389, -2030464, -15034442, 14579451}}, {{4949756, 3799938, 10764212, 630858, 9226631, 5610492, -3364444, -12972929, -33547030, 10727040}}},
{{{-22283174, -8649257, -33076527, -12516302, 17971501, 7223924, -6719359, -16256014, 11440977, -4621221}}, {{18635055, -15919271, -25583307, -1342239, -15422778, 765833, -28318800, 16437671, -7428101, -2214506}}},
{{{12756329, 3094339, -17980393, -2249973, -11348508, 9458762, 15065235, -6816547, -19602977, -8783840}}, {{-26413369, -16249770, -13303357, 14027071, 32795894, -2939378, -17443519, 5188991, 29695760, 4019669}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-20106230, 5033761, 3820161, 14254539, 8896502, 7394342, 16578429, 9332326, 1785096, 12301054}}, {{9147387, -12723968, 956180, 4345655, 18953525, 10557878, 23911328, 5212198, -19262600, -11318415}}},
{{{-11916421, 7468375, 2339370, 2251095, -17578721, 13349755, -29467804, -6245866, 19898176, -5487383}}, {{-14171843, -11479427, -19353069, -5788723, 10851928, -11428858, 7146499, -3201577, -15362408, 7056390}}},
{{{-28768728, 9380526, 427517, -11134815, 11714395, 6667582, 27717904, -170135, -19123030, -8327533}}, {{15095996, 9086320, -11317211, 3577756, -17751304, 4637965, -26593936, -6610442, -20756435, 8351421}}},
{{{18028535, 11484911, -26690150, -11958098, -32372032, 12986430, 16419070, 7435944, 19357997, 15756189}}, {{-15649202, 354434, 22579748, 5969433, -23462534, -12191472, -16206269, 11523825, 4169086, 1339975}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{31381245, 4198026, 23797847, -2744010, -27343257, 36400, 19370825, -9896598, -28788590, -766207}}, {{5972200, 2107808, 20476580, 3962111, -25658758, -3356805, 13809211, -16559554, -21839845, -10050085}}},
{{{28428766, 8750092, 21137077, -5919069, -11942391, -6660789, -32298608, -5120856, -527559, 6248104}}, {{16166812, 3496233, 27507714, -1431683, -21885077, 15771771, 33325966, -1210248, 8207220, -3405686}}},
{{{-11985564, -14922811, -32445122, 10449431, -4747344, -4228265, -23607713, -15487120, -9900349, 2211006}}, {{23065909, -12860077, 7006688, -8107600, -29003856, -3480873, 24597121, -7070326, 16988404, -3518102}}},
{{{15158154, 11972366, 3192344, -9440681, -13758191, -13800671, -3274528, -2459685, -24381964, 2007794}}, {{-30897900, 10361481, 16803125, 1878950, -17338120, 11014920, 26644561, 5112598, 4698068, -3594401}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-13435115, -14362869, -16972213, 5821091, 26575054, -6002733, -27126943, -10230123, -11888006, -9617560}}, {{-5206695, 13210893, -8655605, 1533486, 23655399, -7421641, 13968276, -8451255, -30390640, -16535739}}},
{{{1156472, -10886495, 10105812, -6040766, -24215675, 511317, -32523035, 157163, -30481177, -8937493}}, {{5565494, -8834114, 33479665, 4489451, -16538896, -12374637, -11220682, -4106894, -29236797, 11697294}}},
{{{19846823, 16069429, 15166297, 1718221, 11449460, 9449780, 17048320, 1606288, -29423154, 12914008}}, {{14538355, 11876766, 256068, -11169848, -28604018, -15019686, 11141212, 14170405, 5744383, -6980365}}},
{{{-19902662, -16487331, -24992541, -783803, 13328850, 1167829, -13520876, 10937927, -33439429, -2913057}}, {{21898737, -6691452, -27769955, 14095006, -20202985, 15948192, -172323, -10539558, 2832974, 2200124}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{15897671, -3025639, 21496039, 5624068, 16735573, -14304697, -27784686, -16073466, 18807403, -5652747}}, {{-32057743, 8498334, 10399549, -879074, -7912058, -8884050, 559887, -8032353, 19527008, 6019041}}},
{{{-23423436, -13094530, 29655139, 16083552, 9290346, 15839894, 23187095, 11178854, 9299770, 9501382}}, {{-11738378, -1272120, 32813142, 2130958, -24416324, 11674829, 29164991, 5963837, 9772869, 14541990}}},
{{{-15540620, -5383619, 18733165, -5501213, -22125225, -10278694, 10503607, -5402963, -1923635, 10874058}}, {{2280450, -3779747, -21276671, -11367498, 2792105, 13903455, 2381790, -8368143, 16654124, 5732263}}},
{{{10139117, -563549, 15728261, -12937526, -23750857, 15540786, 2994643, -4871856, -18088235, 1756456}}, {{9135352, -4561896, -13703012, -7229378, -2800887, 4775782, 5577638, -830099, 10482658, 1999434}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{27021200, 5419014, 23018886, 11900765, 26906224, -2829985, -28746633, -10791580, 32865695, -14636749}}, {{-28397474, 5162076, -5417046, -14078168, 16532863, 5345944, -30416118, 16056680, 3677231, -3258503}}},
{{{-6320324, 13093517, 17950312, -1507333, -16929331, -8532887, 26359306, 9025929, 32497874, 15644187}}, {{25252217, 14481152, -9577462, -309419, -32485007, 4951380, 13619168, -11434639, -13653908, 12029752}}},
{{{-30803706, -15763753, 26569297, 15401822, 3746526, -7249098, 4902999, -3067146, -3678987, 10613653}}, {{26765614, -13667905, -10749606, 15462949, 28714794, 12724159, 2320124, -15293088, 10188006, 12035110}}},
{{{-9060761, -13893261, 14481131, -1944527, 10435688, 2282566, 568651, -6063427, 31217439, -15286495}}, {{-8946861, 2593366, 29648688, -15705073, 32206653, -4713425, 13682604, -7412793, -368448, -5230037}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{13908599, 3394038, -5352387, 7269973, 31943256, -12429587, -27021301, 314724, 22458211, 2870686}}, {{-6027067, 7293899, 12931110, 468405, 16214596, 9875634, -18266777, 7761426, 16782157, 8667702}}},
{{{-18412237, -4074513, -4369988, 11939076, -6896953, -10806440, -32922885, -9745277, 22005199, 11393029}}, {{-4060139, -7494228, -23312032, -10792701, 25853644, -6107433, -32993248, 6031079, -6881580, -581524}}},
{{{1161707, 9424314, -6727640, 4689567, 20771983, -6456495, 7498823, 10384724, 19996000, -15411422}}, {{14038644, -1055742, 26406741, 11280507, 14464207, 8415945, 17112776, -14928556, -31741876, -5802790}}},
{{{6019966, -14372441, 11920504, -3953210, -10753780, -7043913, 4836402, -5828855, -12481603, -6328563}}, {{20640662, -1305214, -3526770, 4311257, 3352489, 8036901, -28740635, 6687552, 33052826, 14749119}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{21267577, -12947642, 30939275, -12238509, -11202961, 6234738, -196370, 16193148, -28269388, 10987795}}, {{-11497448, -11020052, -4443180, 16562629, 12759472, -9784762, 27650189, -11430021, 9089774, -5120661}}},
{{{28294699, 13359976, 7468577, 6932231, 7144495, -16313014, 7223290, 6020407, 1313339, 7935640}}, {{31066742, -4076765, 9417000, 8527208, 18827705, -1668405, 26348867, -5498274, -28885504, 3787831}}},
{{{23816208, 14706396, -24697046, 2010568, 15625411, 15770492, -15678872, -6883333, 5322869, -11101003}}, {{11732061, -10139120, 26240518, -56585, 31979992, 1940774, -24811877, 8690243, 24582001, 1076779}}},
{{{-20343952, -10212688, -25201798, -14318604, 17915490, -5160638, 31520088, 2090072, -31673242, -8011258}}, {{-21396979, -13416320, 26418873, -9203088, -2021856, -2124382, 14587592, 11501764, -19845503, 14899790}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{22149028, 10451958, 19030056, -13369913, 26238247, 8618017, 2503062, 2826540, -6850263, -14429883}}, {{-14494368, -3423711, 19387200, 13910891, 21589919, -14012122, 7292147, 5689869, 20698530, 12930583}}},
{{{31248107, 9621310, 31818676, -2756175, -17614862, -13567523, -8192033, 15850649, 14648865, -1746303}}, {{-17373291, 10556655, -1665951, -11200024, -5710202, -6965538, -15942566, -1399857, -858253, -8672506}}},
{{{24043907, -7552534, 25161832, -7538458, -14232945, -6879262, -7209856, -5760558, 28697328, 11865179}}, {{-16631603, 13688958, 31724656, 5363722, 12902418, -3665978, -168976, -7868154, 4677840, -3598693}}},
{{{-21230386, -1709797, 31830627, 8623859, 11542640, 3309583, 32117684, -15156299, -19843562, -13338554}}, {{13220141, -7881020, 24157834, -2427822, 17801518, -16740468, -24532389, 11979673, -28715805, -4913808}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{1211688, 8724626, -24749656, -6944161, -30365306, 16311021, 30024338, 16496604, 27753094, -13799751}}, {{10123230, 15611784, 32774948, -13902752, -19219665, 6767341, -19780601, 2372367, -32819129, -3255844}}},
{{{6946015, 13617354, 8879883, 15702457, 28085076, 11049168, -8394826, -1934303, 13376414, 13565604}}, {{-19234324, -10447891, 19933300, 956296, -2968644, -16679634, -16779131, -10701835, 28717693, -11615101}}},
{{{31982202, -15914389, 2276891, 7224660, -5615075, 5039990, 8847946, 3993837, 3213589, -10814692}}, {{8846149, -6632197, 17132070, -8165418, -12977890, -9368570, -13936006, -15098987, 17256568, -5584009}}},
{{{12185561, 559856, -32627775, 14790044, -28834326, 16161349, 13282392, -6270088, -12074273, -15653723}}, {{-31628712, -16072756, 11830308, 6319065, -990122, -5931888, 26382143, -8730444, 6077403, -2236037}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{21156816, -16775301, -8027480, 9702333, 1787343, 8373461, -20357686, 11101574, -22113100, 11382309}}, {{25693413, 9654833, 19481021, -16035178, 31172070, 5408243, 9833902, -484644, 14737793, -232487}}},
{{{-30538572, 13103825, -9821659, -11182012, 21657851, -4016288, -28955727, 12786353, -8404582, 7226839}}, {{13265128, 930321, 21657991, 6400400, 3878219, 15189495, -29188362, 16534298, 33551473, 6079126}}},
{{{29929187, 6118512, 2547718, -3640606, -25047191, 3577800, -8835658, -6206306, 30533780, 14561572}}, {{28370527, 9087344, 27328816, 11854797, -16259111, -13009704, 15026624, 16247458, -23584336, -9284187}}},
{{{-22614393, 11577238, 4491987, 12741674, 25196742, 8750925, 19093250, -925918, -9961912, 318580}}, {{28724358, -12947151, 21565614, 13460178, -2028417, 15620963, -15100596, 3788594, 25383014, -3724449}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-22097019, -10227030, 30349722, -12949300, -5988533, -15319899, 12599854, -10905057, 32285159, -7408228}}, {{-30773637, -3005963, 20534336, 14952623, 14988143, 11112722, 10999056, -12403067, -13673176, 1147697}}},
{{{-12119835, -14401905, 22455840, 8041343, -23315474, -5060548, 29163904, -11373946, 23986227, 4042986}}, {{23552858, 1173240, -14216209, -13320860, 21330038, 4334830, 19246196, 13541489, -30907528, 16071264}}},
{{{9336146, -9027603, -18416932, -2396949, 25384693, -6658680, -30136995, -5442479, 24269182, -8770542}}, {{6176974, -10189393, 30939265, 7635858, -30720340, -4591634, 33299863, -4764824, 19070643, -9746615}}},
{{{-22301632, -5772422, -26653399, -11185034, 8530548, -7578346, -17080694, -5990236, 29534476, 15486748}}, {{18275412, -9468413, -28562297, -8650733, -23340009, 9425731, 1260695, 16144245, -5561215, 5383210}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-7821280, -5233543, 15816558, 1739793, -22764854, -5837948, 9152213, 689227, 11818240, 6368547}}, {{-18383821, 9662090, -24477754, -14934056, 26863256, -8327309, 6370322, 7682988, -6275645, 16483202}}},
{{{-15508409, 3731519, -16087697, -4925165, -28443130, 3941789, 13333737, 10552516, 18439903, -9956680}}, {{-20584244, 13100485, -24649776, -9526067, 23415781, 10912348, 4143864, -6709859, 9572747, -6448740}}},
{{{19480755, 455412, -17591359, -2241890, -28040763, -11003373, 21053272, 2746474, 20923281, 1349738}}, {{27477121, -1320642, -1069635, 2449655, 24965032, -14358373, -9271473, -12851258, 17649531, -1850939}}},
{{{-29841327, 9803249, 5649224, -11391033, 24977479, -11221993, 19852820, -7849035, -6808068, -11814577}}, {{27783638, 9956571, -29782542, 2928069, 26276732, -10405545, 4609705, -2551961, -1884146, -343417}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-31644616, -7857693, -14849954, 5791594, -25879754, 1993567, -24555886, 12157761, -7789344, -12550267}}, {{18673230, -12289628, -11882024, -13391679, 32323262, -9589233, 4285763, -15498197, -19997182, 12451980}}},
{{{17447784, -10844338, -31487261, 14328608, -6066969, 16737373, 27755728, 415463, -2537066, 11930196}}, {{5961252, -15369135, -6464666, 779300, -553296, 12658634, -1090387, -5108918, -22643602, 15346111}}},
{{{25645688, 5826034, -1401930, -7354869, -22898660, 8554660, 13854186, 3816355, 24152177, 11066672}}, {{15928500, -13217598, 15754181, 5541629, 18720503, -1959027, 14329693, -6918436, 14694706, -9777793}}},
{{{31775280, 5505240, -15920779, 15046521, -24580592, 10720581, 15408514, 14016531, 2520103, -10873356}}, {{17724110, -9658102, -3622320, -9948482, -4768256, 1699790, 9100907, -15053681, -26079694, 2969834}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{17104229, -1671439, 27229469, 1709836, -10061892, 16207263, -32020544, -14109830, -3692611, -11886369}}, {{-29290071, -6008349, -10791200, 9116324, 1365075, 11111558, -17227877, 4835985, 1596809, -12363496}}},
{{{-17576621, 7966754, -19748793, 13774431, 18292864, 6894155, 5757058, -8853308, -23743945, 16565178}}, {{4686723, 1406704, -15764223, 2599785, 3178856, 6327370, -33040553, -3495251, 20045139, -16447291}}},
{{{-7799587, 10364315, -7311007, 359911, 33437401, -3033873, -28219872, 5789999, -22018727, -12648593}}, {{17177766, 10049931, -15534976, -13105175, -5239120, -4210225, 25820188, -6507350, 22709153, -6029595}}},
{{{7202532, -11788468, 15669319, -10491956, -18936470, -13707162, -16362780, -12428391, 5569899, 3862755}}, {{-25805598, 16551458, -16595569, -14177172, -9476009, 10519847, 26144427, 2078332, 27209460, 1232519}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-32618021, 8656442, -21280177, -11420690, 31622394, 1886158, -17985134, -5136528, -26014263, 15586726}}, {{-26350935, -15202938, -13571041, 5530145, -1246675, 23, -3189974, -12976652, -12268242, 13844678}}},
{{{322468, 6546217, 11707630, 5941996, 10001093, -9785656, 17879359, -10020391, 22872315, 109743}}, {{17590264, 10915516, 31924541, -1997169, -20518705, 2606443, 2768772, 13985712, 2597215, -3551997}}},
{{{-25012604, -2358098, -4317456, 11356894, 23428887, -5013569, 8458539, 15378585, 25782520, 5617042}}, {{-22377533, -9307384, -29101579, 3026981, -24674344, -8314931, -3274885, -8619125, 32010348, -5206024}}},
{{{-27579432, 4733574, 32316030, 8576372, 6580903, -313688, -20698218, 14332432, -7483590, 8206885}}, {{-2483745, 1101543, 6669353, -9311639, -904221, -9132322, -10145124, -3988642, -17413639, -9819086}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{12761381, -9560900, 28934851, -13927964, 18600885, -10482642, -29200120, -13555033, -11422906, 2357816}}, {{9677816, 15634735, 19492515, 10912634, -18248519, 15592118, -26965479, -2573549, -25096371, 10281858}}},
{{{-15459212, 5846311, -20230612, 7969038, -18203683, -6666074, 5078372, -5482850, 12971819, 6852623}}, {{16611080, 15625209, 7981856, 16375443, 3180340, -5946195, 12605004, -7118782, 14204497, -2234385}}},
{{{26918440, 9318019, -21937138, 10145272, -2433562, -13104021, -30405356, -9998113, -33552981, -751813}}, {{18135679, -8078671, 7357908, 5561971, -5212259, 5320434, 15235598, -5750099, 14940730, -9197828}}},
{{{32771575, 818095, -27689566, 10841137, 14565567, -16006350, -20187590, -8375151, -1878174, -3705384}}, {{-7822319, 5558184, 223085, 14538687, -33211722, 6075744, -13377705, -3766543, 5447801, 15047977}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{5795984, -3702584, -8841651, -7460155, 19445679, 9208542, 682361, -3396073, 12412725, 12596652}}, {{5635220, -14028841, -31696967, -11765152, -1415688, -4412460, -32128540, -14577695, -3132366, -16570339}}},
{{{12503308, 6309283, -16854329, -7978303, -15995551, 13780228, 24132393, -8059699, -22701946, -16166550}}, {{3061018, 12933579, 19955571, 13662451, -20666533, 11722849, -11455267, 1554356, 14406094, -4091877}}},
{{{26016340, -1842568, 31766789, 11205500, -27821087, 7679854, -30993013, -3088471, -6877545, -369191}}, {{7037463, 2041925, -15872198, -9622441, -11907534, -12260288, 13154119, -3018368, 585759, 3806931}}},
{{{24132117, -3901168, 13993067, -874521, 9133878, 10450635, 30435088, -9818418, -29390268, -5224052}}, {{-23330689, 1819466, 2576361, 11939688, 20741826, -10354008, -22526700, 5337938, 15851765, 6611207}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-2855672, -2473012, 2617570, -5704917, -18213679, -5492733, 24190611, -13001172, -17030721, -10679892}}, {{3022663, -13503381, 12995137, -6709869, 22073478, 15561207, -8398845, -11670731, 3126505, -5433664}}},
{{{-16037643, -12013247, -27193328, -7759885, 30550663, -12599953, -18351549, 3533855, 6547428, 8481421}}, {{8861098, -2516783, -22159597, -1040285, -16957227, -2987628, 11174598, 8148947, -24197611, 13118500}}},
{{{-29028154, -6923711, 10171110, -13705277, -15502847, -12819754, -20401417, 2816566, -31807160, -6033241}}, {{-8538640, 4740779, -17339800, 8940489, 3158691, -16152544, -17546635, -11738587, -29251400, -8944264}}},
{{{33483338, 610009, 12082237, -712682, 11283043, 10207585, -11965711, -1068067, 8666274, -10178002}}, {{16823795, -2372985, 32558902, 10147121, -21234874, 14413371, -27316034, -2154448, 26068272, -16085685}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-15487198, 5107534, 12621198, -14327014, 9942495, 1433656, -25152940, 2767298, 16501392, 1077260}}, {{-8324708, 13628354, 12385590, -11408862, -7100943, -10593257, -18641357, -9479984, -27335616, -3597863}}},
{{{15573525, 14345213, -21141567, -612142, 123758, 10521238, 28338138, -12928375, 9171680, -7828746}}, {{-18590957, -4287007, 23122404, 4576385, 22037208, 1801295, 32339603, 310189, 3056877, 825069}}},
{{{5248612, -6851233, -16968897, -2985068, 31141260, -1962891, -20362183, -1523877, 31913422, -5987720}}, {{23505933, 10678491, 5677783, 6319367, -29715724, 15887385, 24018158, 10793161, 25997641, 3936363}}},
{{{-2382441, 11176803, -29285848, 13491360, 20582427, -6248431, -2943597, 9999820, -21199669, 585503}}, {{-14038527, -12290108, 28958129, 7955216, 1303854, -9304343, 1055631, -10315478, -25977137, -13324705}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{20566396, -7536913, -6416232, 12027771, -27266655, 7522376, 22161883, 9745153, 16192379, -4898405}}, {{-31874006, 13747285, 19622806, -6221451, -1751037, 12064856, 32615775, 16322677, 25338024, -11342285}}},
{{{26436284, 16396193, -33437362, 10579374, -11622078, 10349235, -6440143, -5650815, 28083971, -5400490}}, {{13276869, -7960398, -29561858, 1643266, -13005790, 4469434, 27078316, 10525843, -17592579, 6780208}}},
{{{18334304, -10868643, 7919738, -3728864, 18760742, 14946111, -16962487, 8651760, -3807863, -4454297}}, {{30987827, 15324452, -24550370, -7876558, 5357345, -9149168, 16262922, -408371, 17778957, -7134441}}},
{{{-28270023, 6064385, 27909662, 4631705, 14859164, 10819831, 6363673, -12741410, -28854756, -3755418}}, {{24432421, 6981333, 534293, 11316906, 24670894, 8274364, 31397898, 12488994, 167614, 15358731}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{4552491, 10328571, -579194, -10907345, 5480238, 15614817, -4665891, 11082334, 10599350, 8940622}}, {{830871, 9866758, -13428201, -8274437, 25320767, -6573280, -33260724, -8391538, 23047040, -1751350}}},
{{{-12624856, 12983031, 10103687, 3076416, -19610294, -5638468, -7053449, 11523690, 22918816, 7367734}}, {{-20724248, 7602855, -20912186, 5637234, -13974134, -14807337, 5633999, -6854221, -28442537, -10553992}}},
{{{-30989857, -13992076, 24916435, 3605069, -22903655, -6708851, -23864817, -13040210, -9051388, -4517559}}, {{-752215, 12938298, -24940410, 13111505, 4109551, 15363139, 20907935, -7504965, 21424117, 4128175}}},
{{{-25387174, 5299990, 30892946, -14552174, -25001298, -2575136, 6200644, -15128299, -19730692, -12709441}}, {{-1037011, -16081017, 22363918, 13600523, -26632570, 13243349, 18079077, -4967086, 13493510, 2660611}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-17678689, 15967277, 6802587, -5128472, 31048017, -9849564, 30440962, 11947653, 26001632, 8235135}}, {{23092780, 2201114, -27810252, 14772042, -18213047, 11035713, -33063878, -13289884, 126599, -2202223}}},
{{{21967487, 14102271, 13406647, 16484947, -21590556, 13957518, 3401718, -12533938, -17374987, -4445665}}, {{7223001, 4793115, 14142465, 15885969, 25110621, 8899613, 28647796, 5224825, 1265753, -5406642}}},
{{{-3336716, -5520764, -5624470, -9035608, 30545997, -10040508, -28386506, -7976241, 13166811, 15086130}}, {{-25929251, -8666041, -7913746, -3081765, 17105808, -614877, -3075863, 5027256, 10852020, -59486}}},
{{{7996772, 12898977, 30809816, 10181843, -9909843, 7697626, -21865118, -6224024, -17538802, 8274720}}, {{-29741170, 6844980, -28964977, -5160415, -524556, 9945333, 31581784, -11063486, 12468586, -7548621}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{30625306, -7552437, -4081086, -14206474, 188076, 11397259, -28918443, 3482887, -25405112, -14765812}}, {{-8746716, 2551140, 8419422, -5704061, -3224940, 1763701, -18481525, 1932611, 18044609, 10656519}}},
{{{3790284, -9885313, 29533782, -5816114, 25194669, -16384879, 7231957, 1606960, -7313518, 9145089}}, {{31566030, 1432610, -20477309, 9703536, -27649004, 14891271, -20260356, -1778947, 21340316, -7572506}}},
{{{-30569429, 10560231, 29321950, -4458123, -8076301, -4552394, -13183961, 1143194, -23220733, 6046817}}, {{22717996, -9378599, 31737399, 8370074, -15948884, 13560701, -13371837, 10923471, -21133388, -7076278}}},
{{{10147133, 5086425, -15672618, 5372437, -2678842, 10266691, 15619113, -12065633, 28985877, 6917025}}, {{13155781, 12809541, 13941821, 4754463, 22311936, -8498813, 12615739, 12261751, 26877532, 8238175}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{31783402, -2836358, 27470376, 15650536, -31668658, -2815708, 13202882, 7196353, -30666866, 14341531}}, {{20560698, -4158277, -15775619, -14933854, 24856852, -8856172, 27667141, 10236878, 17052654, 7305515}}},
{{{-7346254, 15821049, -12726695, 16761356, -15362117, 2586438, 28073630, 10243770, -27544400, 4137934}}, {{9665316, -13062835, 1681679, 12357725, -3086950, -10624335, -22170339, -3210519, 1646002, 6022258}}},
{{{-19800298, -4557481, -26039542, 4885245, -14374132, -12036651, 22139453, -11773834, -18970421, 7136543}}, {{27187782, 7966356, 28800218, -1031206, -3189197, 16252224, 26656802, 16386410, -10742136, 2088803}}},
{{{-28962553, 7646704, -20194854, 2014484, -33057936, 3995227, -21145745, 10912820, -12935318, -8243318}}, {{-26131206, -4845442, -18715879, 8136538, -9232808, -8738359, 9951554, -16558554, 18086286, 15517504}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-30091903, 15253574, -24486574, -4415643, 11814407, 11925848, -14166779, 13100511, 27474931, 2312093}}, {{-29176019, -1215700, -8878289, -13204773, -12542619, -15568554, -31538097, -12042924, 20254471, -14715314}}},
{{{22137199, -9795813, -912193, -8974174, -683462, 5169325, -27200879, -12499656, -32892441, 2932526}}, {{-13485585, 5318781, -15173443, 3977180, 13685969, -2218520, -10853558, 7392687, -24208287, -7600426}}},
{{{5413426, -13212199, 32121092, -11212493, 17616463, 15300602, 3067313, -14848349, 16285560, -13184762}}, {{-24991706, -12256688, 20987254, 7263870, -14830625, 2022523, -22584265, -11531189, 6342543, -12254490}}},
{{{30649895, -14429437, -7357113, 8148778, -10335889, -4975055, 33536722, -6748931, -18078010, 2917812}}, {{-15549738, -1406315, -16566865, -9153876, -16114303, -13069969, -21159991, 3269785, -15864747, -10960561}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-27984382, -9271803, 7148720, 10710298, -23746392, -1625457, -9328718, -9975655, 24946235, 16634392}}, {{29451294, 16192671, -7066814, 13595253, 20114594, -5657362, 5325966, 9398055, -26992388, 4175400}}},
{{{9190643, 8659168, -7731471, -66139, 9428529, 16766471, -21610160, 12355439, -26326085, 2343236}}, {{7728738, 9233554, -21643618, 854993, 13280536, 11962374, 10134427, 11032215, 9373544, 14827521}}},
{{{-6482607, 7628145, -5466265, 788653, -19185245, 8203429, 1868079, 8879104, 31239370, 4231684}}, {{-448006, 9549390, -3270229, -337296, -28885353, 15658997, -1567547, 4503709, -9439063, -14183439}}},
{{{12124349, -15900863, 24780160, 9539624, 9577961, -2011019, -12517070, -7291662, 4550433, 9833693}}, {{-3235422, 11966515, 19120194, 1659337, 31436508, -3544512, -18180586, 15044560, -10836, -7649516}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-6780899, 8328087, 12625032, -9348473, -10140069, -5082516, 4989210, -12445843, 30984102, 1495070}}, {{-6332113, 13625910, 19009936, 8336515, -24277173, -8497947, -32918285, -11865596, -31113573, 9217293}}},
{{{-17294088, -7635133, -31539536, -10875924, -17041338, -11152998, 6264981, 11375352, 32293725, -5806547}}, {{27217550, -14647799, -22952533, 14420647, -12957030, 9431372, 6626706, 13985948, 8372195, 16292690}}},
{{{27038479, 7797188, 7388702, -4675262, 10451829, -12669473, 32516005, -13623605, 5488982, 4782814}}, {{13434869, 12889404, 10038240, 12119644, -13438080, -5676540, 22235718, 16343829, -26961710, 1856607}}},
{{{30717676, -2443993, 25226774, -1249151, -7162809, 7353127, -32621495, 963567, -6339226, -7691615}}, {{22396731, -14493619, -10677527, 4590250, -27790097, 6295850, 15044427, 7885730, 6404256, 16062299}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-28307823, 12809005, -9554739, -1086957, -4017473, -6155523, 7153440, 8282685, -31437294, -13078514}}, {{-14962213, -10986276, -6183704, 16329684, 12335565, 2422419, -28825620, -11774890, 26615553, -5675997}}},
{{{5582210, 2329598, 21455646, -7260433, -272570, -1656602, -14415766, -1619671, -21735958, -23998}}, {{-9865517, 3038925, 14536200, 15423821, -30050493, 4865730, 30972917, 10510400, 30576403, 4981758}}},
{{{-32318579, 14721717, 31703904, 14835661, 32684794, -13986588, -13543022, 8371441, -2516318, -5225297}}, {{14001805, 3352427, 7335597, 15358574, 4648371, -1744806, 26459871, 11967313, -26198167, 16665233}}},
{{{-4860382, 11526406, -24872574, 10943057, -24710972, 11234989, 25734141, 12908138, -13336674, 7917841}}, {{10943609, 869101, 4831524, -11656159, -30953341, 6732437, -2317269, -2535439, -27340702, 10839383}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{32891241, 2815356, 20301173, 11960220, 19909245, -15156175, -13794475, -15976808, 29387568, -13455866}}, {{24537119, 13501824, -17899035, 7552149, -30561767, -15931162, -23291012, -211337, 25941485, 8143852}}},
{{{-15863658, 13958105, -13797715, 16153632, -26441709, -2094547, -27005869, 13923508, 17626879, -941650}}, {{-2681549, 7685792, -15168764, 6784297, -613937, -3073797, 21416066, 9730634, -22340294, 15480}}},
{{{8603871, -34460, -13283192, 13374560, 27316369, -14476209, 12117613, -946180, 978715, -2194728}}, {{-10413304, 2575870, 20864640, 678779, 18114068, 163661, -8211138, 2354569, -24296952, -3629756}}},
{{{31799852, -8946389, 9150182, -16065110, 25044621, -3521130, 9490983, 10178067, -27653044, 2864084}}, {{18966535, 146009, 21840244, 372178, 7291582, -11799099, -22009798, 2960934, -32767770, 6603009}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-11045405, -15254833, 19532483, -3816834, -2978693, 11138476, 21629584, -7152816, 12949938, -12069890}}, {{-7980351, -16667594, -6066191, -4178266, -20661758, 5435061, 13465372, 4095711, 9258724, 14070358}}},
{{{29333332, 10934940, -14778994, 7811936, -23747152, 5400624, 4239596, 13102200, 16856010, -10864742}}, {{-13616645, -9680674, -3693696, -365662, 15298234, 943540, -26336867, 13166652, 10038926, -13557624}}},
{{{27219864, 8499757, -1510410, -13117566, -26294616, -8546704, 11719293, 12996257, 7861962, -12796627}}, {{-10884812, 632677, 27150992, -13757978, 28020245, -16489791, -23526316, 8860718, 7583912, 4998526}}},
{{{-30145574, 12792090, 9932238, -7877207, -5944826, -14451467, -10727441, 4439529, -15215278, 13437714}}, {{-9881640, -9328105, 4166804, 3359603, 7561129, 8245863, -26838787, 10932651, 32509075, -12477005}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{21122458, 15275850, 22351341, -2323860, 14384970, -14548497, 29812323, 6794013, 12567819, 13523550}}, {{471974, 3314354, -4884934, -1753362, 18152114, -16266037, -23404599, 5224820, 26284993, -9225139}}},
{{{-12470203, -12457226, 30523395, 1939198, -9435791, -11468299, -13825973, 296095, 9675162, 16689320}}, {{-18116881, 7827442, 16576354, -12683470, -6088996, -11805557, -14841172, 7420237, 14340058, -1542268}}},
{{{-4198519, 7609665, -4625915, -9570636, 126335, -6772174, 21471223, 13646194, -28954603, 15000206}}, {{14066827, -9786092, -20149108, -13301388, 32694991, 16078458, -29219026, -10764436, 8959117, 13822693}}},
{{{-18291771, 13223404, -30667620, 1133116, 24528956, 13144848, 24563847, -7154377, -16290734, 12838709}}, {{12431509, -1446109, 31436746, 16644562, -33430511, -6333908, 9483304, 1625635, -22798318, 11713407}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-8491357, 2415699, 25013848, 12133263, -364390, -10928436, -24652787, -15216721, 32075362, -8273324}}, {{20866716, -6827257, 6330400, 13248178, -14764332, 7461923, 15675924, -1775864, 8827593, -1121568}}},
{{{19361853, 7075431, 7726326, -3083537, 25514177, 12839008, -10609389, -5226832, 4200014, 8061868}}, {{27536602, -13571980, 15093196, 7717112, -26838940, 10105642, 7781719, -7526323, -7655304, 16242865}}},
{{{11905636, 1662562, -19754617, -1459433, 15414674, -1507349, 23299265, -6215155, 13644417, 2772584}}, {{32613186, 257329, -21907173, -3806839, -13226976, 16484873, -8453236, -996782, 10406895, 2254153}}},
{{{30779663, -3003776, -28523254, -1716014, -33536086, 10164248, -15547349, -8237791, -23761245, 6590726}}, {{-17817122, 8315575, 18462486, 13374294, -14717492, 15435984, 28833611, -4570913, 19380189, 3291296}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-23640941, 12569140, -21460985, -5972040, -32498256, 14194940, -8272266, -5685877, -22321601, 10642431}}, {{-13298115, 15667645, -19341674, -5778818, -6795644, -7125672, 15425117, 9370859, 23770825, 2440430}}},
{{{23852890, 5489792, 9312298, -7193436, 29732871, 1559767, -22247501, 2231212, -11463312, 13863800}}, {{2087206, 15406615, 8011889, -3113938, 28704525, 13469326, -20465111, 14872299, 9140459, 7302058}}},
{{{977609, 4728016, 2967215, 3855395, 31450548, 6942063, -15563122, -8513137, -19113026, -10708085}}, {{-15800094, -10525285, -6675202, 8834378, -32349531, 15697503, -8619925, -2051806, 22412691, -1716868}}},
{{{-32088869, -5768320, 25086661, 5586170, -23594476, 14518157, 27748172, 4893464, 25417659, -13445713}}, {{27277432, -14025083, 10318327, -8070090, 20282005, -6649110, 32247120, -14513557, -12176814, -9142849}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-21196865, 10673992, 32612715, -7769163, 29159310, 4075347, -18199864, -7740793, 24961993, -14296975}}, {{31543464, -11150632, 23633255, -3444640, 30539928, 7311346, -20996291, -14033306, 31524433, 13145101}}},
{{{-2334532, -8824572, 32619588, 7437258, 2192, -12355835, -4907373, 9959161, -12169088, -7000856}}, {{-15590999, 15587995, -9913444, -12212515, -22842693, 6636565, 18507569, 4395155, -30470127, -12371472}}},
{{{-13622975, 5359317, -16574752, -1393641, -4095345, 6026803, 12851320, 2075442, 22780457, 13665869}}, {{-6395990, -4302149, 17726158, -10400929, 133520, -14902872, 6559759, 13765202, 15206059, -12242947}}},
{{{6520079, -6874205, 12314140, -8292397, 1349263, 2473300, -2686115, -8703620, -13398366, 2381847}}, {{12553415, 2837017, 32199871, 11392587, -10791425, -13670722, -14002913, 4609887, 18999714, 7852053}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-4513859, -442437, 26623889, -6011463, -2693348, -899547, 21483475, -13757839, -20615865, -15197192}}, {{-19962290, -13398764, -32187614, 11204275, 23307966, 10219258, -24653092, 4750343, -26847528, 3933032}}},
{{{3831182, 7657791, 20688837, 10144978, -23145731, -16403629, -11017770, 5284675, 6955812, -15931414}}, {{-6075615, -8412519, -25285867, -11211287, 16898559, -15695504, -10629957, -14499464, -12178513, -4972751}}},
{{{-3739178, 16488805, -23242879, -3797119, -16112108, 15390666, -28056294, 1749817, 23901845, -947065}}, {{24964012, -2548532, 12685293, -11770541, 10193478, 14820307, 18427579, 11254762, -3442436, -4010478}}},
{{{-20512258, -7100978, 28046711, -12725920, -8825454, 10944445, -18251146, -3487950, -28340506, -7811908}}, {{-4657307, -2952664, 19152821, -5466918, 2841097, -8785253, 18326521, -790579, -4185715, 16281581}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{13142850, -13347760, 8479574, 1381711, 12346501, -4221061, -4805636, -1448024, 1781281, -1148926}}, {{2852236, 16547633, 5192981, 12330529, -31725336, -426585, -8275974, -14048245, -15274088, 2416978}}},
{{{7612755, 5737450, -25915585, -1193480, -21969712, 8939931, -24069233, 5389926, -14593435, -311653}}, {{4661446, 14641435, -8565639, -591845, 28706337, 4327374, 29306892, -10499409, 30256951, 4347437}}},
{{{-15866782, -9048831, 14139226, -7561478, -23023550, -16140740, 29505539, -13302488, 17362774, 8609680}}, {{-14908841, 1617899, 33070350, -9353338, 2158682, 8751480, -325725, -2524688, -23962744, 1042796}}},
{{{-7170546, 12522521, -2843124, 1098851, -19099553, -5651847, -15125132, -1006277, 18406587, -5281714}}, {{-20837834, -9874706, 2285804, -15533686, -28581606, -12032262, -20196550, -3076190, 3872303, 11599520}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-26169014, 16394851, 4198188, 5288239, -24101585, -15094425, -30161840, -10989214, -19745355, 6733398}}, {{11967902, 11343923, 19065326, -12430637, -24728366, -12832186, 3752898, -15799674, -10503449, -8877521}}},
{{{25672196, 7270733, -18957833, 6729327, -6800912, -314223, -24174295, 13849998, -23495612, -15270711}}, {{13016697, -8687607, -24048715, 12296071, 33532398, 2228034, 18337232, 15368115, 8929397, -11897311}}},
{{{4757190, -4093299, -24661354, -6915880, -16218364, -3645885, -11461992, -6339288, 10377281, 1700298}}, {{16999730, -5660039, 30111342, -565676, -30582644, -11856802, -18907993, -6496585, -12011594, 13648976}}},
{{{19056135, 2570373, -14470068, -4361921, -14247623, -7231871, -22771384, 14876701, -24281836, 15043721}}, {{-33496325, -5784416, -22596828, 16115749, -20320868, 15117351, -22843051, 14490779, -3490856, -4364970}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-9542601, 1854823, 6715855, -5138168, -26357819, 9115066, -18369386, -5636694, 20006261, -13200888}}, {{683621, -4073879, 21855811, -5017350, 25883352, 14333668, 14567889, 5914789, 3434301, 12910680}}},
{{{23950156, -9932987, 23227274, 12595488, 23884258, 1581035, -18046550, -12890933, -7437805, 8980723}}, {{-16200249, 8963420, 27541859, -12611953, 18206495, 13541107, 16473019, -13510969, 29268968, -7735490}}},
{{{-17015918, 7257949, -7020610, -15786836, 1025278, 13904852, -17961840, 10995274, -29998817, 13302484}}, {{-7333991, 520826, 28136610, -2194999, -5858543, 14291802, 13660941, -16119913, 22529036, -16160552}}},
{{{-13497420, 4273963, -3921238, 13346905, 14011942, 2855226, 19198975, -13095203, 20681840, 1084425}}, {{18766588, -11133689, -9308973, 12186812, 11920620, -1091674, -24805085, 7589322, 26409177, 1273463}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-11085869, -6007258, -1449668, -8184331, 17701391, -2048931, -4530054, -11415176, -28786821, -7421510}}, {{9154070, 599800, 4754317, -4700538, -685585, -2828160, -25253796, 3662694, 15571284, 7102306}}},
{{{-29928058, 930020, -17390967, 10829461, 14140693, -6408124, -27587079, 13074439, 171753, 2929576}}, {{-23471363, -6240664, -19059283, 9077820, 25228279, -12466553, -9582739, -11183156, 27430202, -14701993}}},
{{{28999907, 4680582, -78027, -8721054, 11042394, -5101106, -25650176, 10588659, 28025483, -6563706}}, {{5569301, 8175982, -24303024, 3467826, -10600998, -10065159, 5501824, -5513486, 22656685, -14518287}}},
{{{-32265539, 9532282, 21705865, 12946208, 5034842, 9954820, -26901686, 14117339, 24976601, 1806149}}, {{-12227443, -1773302, 5214128, -3030397, -31271507, 15849927, 14453948, -14175641, -3551731, -3418311}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{19130916, 9115039, 10603324, 4203268, 7983466, 1306443, 33531501, -1005392, -20361084, 8146049}}, {{2580315, 8427300, 15668648, -677150, 136226, -163846, 8713215, -9445822, -11091070, -6763083}}},
{{{20317075, 3746592, 25600292, 16093738, 8671536, -7673370, -8436034, 2611396, -25189540, 7682500}}, {{29503092, 5629303, 17831290, -5719265, -30699229, 7511570, 13026015, -114358, -23998966, -1269729}}},
{{{-32214578, -10286696, -6473464, 9352860, 28581055, -270362, 13429565, 594635, -5005068, -3505462}}, {{6896462, 6115570, -19976822, -4301021, -16169316, 737837, -32489110, 12648484, 4980086, 782680}}},
{{{12052535, 1174424, 8175504, 5117753, -27026921, -11654751, -23281039, 6656678, -801697, -13590848}}, {{-678274, 11486291, 9685879, 15895846, -29146376, 12753979, 9394963, -15748418, -26925347, -8605080}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-31137640, -758515, 5062558, -7045635, -2468686, 8220389, 11271112, -10554352, 7552766, -1986676}}, {{-29481143, 12698802, 20433365, -680725, 11137059, 16582727, -7903510, -16030075, -9243830, -7018114}}},
{{{3058195, 572435, -13210217, -10528151, -15035582, -3613283, 11255982, -14255119, 300683, 8911762}}, {{9443091, 3471948, 4597260, -2864234, -17394470, 8749882, -30486360, 10725422, 29387, -12571171}}},
{{{15479927, 5318576, -19655192, -11311062, 18388164, 10298421, 13295299, 15256926, -6993587, -8981264}}, {{-1942646, -13078066, -949648, -11281443, -24310983, 10037946, -26451884, -9039672, -8950112, -10758178}}},
{{{21410802, -3875964, -20331241, -9990421, -15899977, 9734393, 13370159, -9610092, 30707888, -2098647}}, {{32834118, -9344023, 12012975, -1027670, 9089832, -14578287, 104907, 6476120, 1967007, 15813692}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-13142713, 5475592, 15532981, 12734403, 20181594, 16226149, -30857983, -15228882, -19809355, -11564396}}, {{-23341716, 14952599, 25622298, -12315990, 33307681, 6652330, 11077232, 15094905, -2251198, -9925420}}},
{{{17608885, 14609619, 21231876, -13422132, 4272876, 10275383, -3210562, -2156512, -17237223, 9986462}}, {{1261899, -16348971, 24455637, -1943308, -18050984, 11979647, 24808847, -7677666, -32890065, 11174254}}},
{{{-28890716, -1799262, -26615254, 11199896, -18441989, -13376823, -8351863, 15955474, 4192860, 10516542}}, {{24783152, -10241240, 6116791, -6094016, -23826266, -12859184, -32127553, 1349040, 26546548, -9127439}}},
{{{5205021, -3371089, -27047587, -4043255, -15999235, -9728044, -284329, -10160230, -10062835, -10897610}}, {{19378424, 10940331, -3377474, 11082199, 33041118, -12214541, -23294792, -5819921, 33292532, -12081210}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{1354376, 6627721, -12074430, -2202199, -11111549, 12217757, 29800748, -1088417, -16169014, 8734413}}, {{-29526794, -4969475, 7307364, -1684647, -29245288, -5989667, -16898818, -16342712, -1161484, 11011394}}},
{{{26665961, -45416, -33295490, 10560805, -8707732, -14831279, 19592280, -4083471, 2341552, -1166158}}, {{11472005, 5316862, 32029481, 13256638, -3747505, -1990554, -24454686, -822978, 24852005, 7411349}}},
{{{-1437041, 4715628, -20880881, -11281120, 22949556, 15163954, 2656515, -3643532, -8254906, 3619014}}, {{-20808572, -7805846, -12871750, -5329288, -6780734, -10337286, -21300345, -946188, -13744160, 7503538}}},
{{{10076571, -12120268, -25299316, -3374983, -28001061, 14468758, 19432815, -6393412, 33473820, -8484153}}, {{-6199250, 2547529, -9392856, 8780308, 16996654, 5429039, -15673047, -15225700, -27861959, 16648171}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-12059141, -6708577, 8769332, -4228077, -2379640, -16152871, 32423449, 724288, 29063034, 8265266}}, {{14960488, 5590890, -4888956, -5831311, -15241300, 12540090, 12883298, -4291770, -8606189, -10150299}}},
{{{23317191, -9809296, -3495769, -7133484, -2277347, -2184141, 13478971, -1616318, -6324398, 2332690}}, {{-14484922, -4686189, 16749280, 12271059, 7315218, 6262918, 11401847, -4606398, 9187051, 7122353}}},
{{{6437347, -15969299, -21276383, 12225439, -3218667, 7357348, -29314830, -557999, -28711684, 1692027}}, {{-21463, -6916086, 28542776, 8829976, -19114964, 2933474, 20986264, -9719897, 1488267, 9163715}}},
{{{33259537, 7446349, 8717408, 16605206, -25767672, -7077635, 23426899, 2175739, 30963572, -1958419}}, {{26278901, -7970741, 11380212, 287812, 17161585, 1638733, -25939909, 8161546, -20764621, 853714}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{29495551, -14969918, -2360737, 14933588, -24188812, -9971017, -12326374, 141671, -23437230, 6168325}}, {{-3500298, -3262836, 23036789, 4715502, 18844196, -10655189, -28246746, 5692375, -11201764, 3052420}}},
{{{13034844, -3480703, 10950603, -4302564, -22724869, 1208020, -10917163, -12242330, 25724074, 513292}}, {{-19137456, -12036503, -26224718, 3767666, -27312022, -11727416, -17334094, 1937537, 11177428, 2998588}}},
{{{-16684735, 11851546, -395087, 9092746, 326047, -3427015, -11850943, 16275141, -29379122, 1663582}}, {{-17625588, 12155951, -18155945, 14222900, -17264090, 9084147, 14726365, -11930082, -18243501, 14284868}}},
{{{15279679, -12518832, -30596906, 5148421, 31854978, 7153630, 22985587, -15344419, 425013, 12531039}}, {{31244671, -5295634, 23766961, -2371262, -1893064, 2779069, -3692880, 14893409, -19944463, 6878879}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-18006127, -2226664, 27624552, 140384, -5771360, 13751951, -13915109, -7768620, -4165450, 11359663}}, {{-15250046, 6371446, -32100581, -6719507, 16541399, 12646939, 7264692, -5167680, -14153748, -1146803}}},
{{{-12554470, 1118508, 28436598, 2160256, 24405039, -4063602, 11428602, -4153582, -11990043, 16609567}}, {{-13878333, 5029821, 21487854, -16634411, -5622110, 3787605, 33118728, 4364881, 14709800, -11668570}}},
{{{29470384, 6550115, 32436055, -16527913, -2711309, -12590485, 32604207, -10188631, 22512696, 7908469}}, {{-19482604, -9954874, -14928093, -7520989, 12442845, 10424971, -10248198, -15053625, -35477, -16311854}}},
{{{11860080, -13153238, -25909478, 9356887, 13028323, -9251695, 27601795, 13193287, -31324532, -8059804}}, {{-7482324, -12285358, -16632307, 6138428, -1403249, -11238138, -20211243, -2603662, -24946272, -7360619}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-12632143, -12765636, 1316480, -10997117, 29444261, 2362133, 11533330, -425201, 4823200, 5159558}}, {{-21487804, 3162225, 11182886, -14646528, 27047347, -14293648, -18876146, -9560196, 29936147, 2232914}}},
{{{21218535, 4911699, -8148051, 1957242, -27182879, -15864514, 8290705, 8975166, -23491840, 4049238}}, {{-15343778, 2199253, -31574512, -13337788, 19151346, 7067674, 24618879, 8030457, 17005584, 5965425}}},
{{{-20568883, 14713616, 2454067, 8229459, 24991264, -43174, 25541235, -16775070, 19723966, 11537495}}, {{18218972, -2978856, 10374214, 6662520, 16546524, -15787404, 15136108, 6213563, 28504289, 5827947}}},
{{{-12110053, 10993017, 15025565, -6179817, 18744448, 6900626, -20576121, 2845292, -4160904, 9878147}}, {{27341436, 1082433, 25901632, 5968493, 21203022, -6447011, 22937294, 3057698, 30198244, -8948961}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-29826068, 10228098, 19205072, -13632566, 10828617, -5241203, -11675886, 1031309, -29812980, -12864525}}, {{-29945227, -4355045, -8216732, -4689813, -6444537, 11273481, 19078229, -8565124, 3674229, -8750607}}},
{{{-14550532, 14519188, 328691, -7201861, 6224501, 12986928, 20138252, 1246732, -368364, 10621026}}, {{13871935, 6136509, 28919700, -11134391, -32232412, 12790296, -97226, -1592341, -24740362, 13107466}}},
{{{-31760284, 6460354, 17241924, 439765, -26236967, -11121289, 25505169, -5642797, 8595476, -9544068}}, {{-18070299, 6563650, 1733615, 8223695, -8915902, -14176763, 10068812, -2679473, 26586277, 3900765}}},
{{{32758298, 1101929, 15720325, 3625871, -13540113, 4248367, -7742986, 7973006, -14451935, 7562684}}, {{23124982, 1218355, -25304605, 6523316, -19904550, 1560281, -7133265, -9702673, -21422339, -1472084}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-6141416, -10468826, 26775654, -778362, -28035150, 16472909, 20991101, -7680823, -13945583, 10318868}}, {{-21448370, -7629182, -17803136, 9247970, -23433092, -12033061, -17869106, -2648890, -25320665, -10521195}}},
{{{20402052, -16015540, 15791544, -4499120, -5406735, 3503439, 22409043, 15156001, 19856155, 15789482}}, {{26522171, -15200677, 3997142, -5121836, 1405470, -12244332, 24428637, -10422748, -16129011, 4830502}}},
{{{7870717, -11326943, 13315536, -7624915, -32335768, -4107985, -25622123, 7056739, -16812779, 8914688}}, {{6441892, 12548499, 4079854, -1075228, 27390027, -4576650, -2575621, -16694556, 785156, 11260899}}},
{{{-11181995, 4684055, -9197170, -13400837, 11692567, 3334816, 21980964, -10423131, 6737012, 15956446}}, {{-25552630, -3088474, -7686869, -6966664, -7092222, -2927912, -12395670, 10022463, 24638452, -1586481}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{27773510, 14573269, 11229534, 8875955, -7213999, 6630085, 24965455, 12866809, -31673038, 13016429}}, {{-20588637, 3097098, -15963530, 15830555, 5577173, -481647, -24900328, -16387827, -3207094, -2358854}}},
{{{23142804, 5488002, 8245854, 3906315, 3756830, -3585214, -10721116, 15643184, -8222317, -12451977}}, {{-20934756, -682128, -4320236, -2722803, 23224813, 7919547, 9019364, -1888610, 10063758, -8394378}}},
{{{8730014, 512485, -33242446, 5729319, 26205698, -14186942, 3865196, 1285003, -33037780, 8385749}}, {{-9499032, 14429862, 10605687, -6254497, 18838156, -3086600, 1685010, -3615947, -6012681, 4006363}}},
{{{-10409309, 9861262, -12262974, -9299162, 27593475, -14769031, 25871765, 9830173, -13202899, 9562837}}, {{20125996, -13973769, 7733310, -10872895, -5627879, 11582, -22889451, -2250998, 9716451, 13578165}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{32008371, 2384848, -33398209, -10667659, -21513021, 24993, -9570364, -9729158, 23889452, -3406875}}, {{-20881345, 2673505, -3896571, -7922435, 20457266, -15646950, -33322359, 537736, 11155038, 4568324}}},
{{{-33472444, 15013269, 22103307, 13070997, -30141397, 11187662, -2810857, -8457993, 11554739, -11471341}}, {{-27660512, 13297976, 25546194, 10801687, 18600119, 2828120, -20854900, 9686312, 5989357, 877559}}},
{{{-3569357, -3729255, 9180803, 4931894, 14465804, 11827983, 33348430, -16106849, -22659960, 1908192}}, {{-15158203, -13443502, -25105573, 11337849, 17253043, -10376384, 18182802, -14750235, -17339061, -5171296}}},
{{{-10461535, 3702484, -22811314, -6272389, 14208599, 98758, -7175412, 9868421, 3697218, 700720}}, {{-2213769, -3008458, 17735169, -13981699, -193340, -14550152, -2523260, 12356961, 27247374, 429488}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{2934035, 10548459, -18534512, 337968, -31949096, -2689962, 5015064, -9212742, 3200103, 10509281}}, {{11829041, 7102365, -12383759, 3351899, -31647876, 13003489, -26966152, -12122459, -12238065, -11449581}}},
{{{-2318359, -14520240, 8711817, -227825, 15899948, -733714, -3534193, -16593808, -1684539, 3347032}}, {{-25880162, -8290084, -11670196, 10427489, -8140637, -12354886, 6943541, 15720408, -4797767, -16232902}}},
{{{24169191, -70961, 25168844, -15483296, 22406113, -13278546, 31673726, -4088704, 817855, -11395545}}, {{28224818, 1103393, -2304457, -3874814, -9610718, 7994525, -6226693, 3643116, -10350703, 11357297}}},
{{{22749274, 5319016, 6309010, -3989357, -8660649, 4709165, 25518940, 7274520, -10527351, 2662500}}, {{10099670, 9550171, 28495389, 9523828, 19699845, 1031089, -28453698, -16107679, -28725487, 6418907}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{16225530, 16118800, -19901123, -3625302, -16914225, 6550155, 16423893, -8931957, -1875156, 14837199}}, {{-19221697, 5207583, -23439021, 7655128, -18980546, -12669195, 1754960, 10908812, 19941959, -13259066}}},
{{{27827626, -10557965, 12384052, -12062851, -15880949, -8559517, -10187309, -14108076, -16761108, -6094081}}, {{8697856, 7667083, 27561332, 12235835, 25814374, -1200993, 12903674, 6325700, -1901365, -13882533}}},
{{{17129785, 14829947, 23292849, -6117274, -30932564, 2025543, 23347683, -6590773, 13083037, 2955679}}, {{29544275, 14330728, 20052414, -4135178, -1950284, 15155831, 12147071, 9224516, -21268233, 376724}}},
{{{-26506206, 1277744, -28455858, 4508603, 22932986, 16649594, 13187438, 14920990, 14142841, 14434638}}, {{-25720730, 651905, 4766901, -11385529, -14130515, 2764267, 18582442, 1802534, -2394962, -769526}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{1991837, -15351163, -20210853, 6294749, -30474851, -16187855, 6981358, 2177781, 20588625, -266985}}, {{12750042, 404276, -24720803, 15538447, 31754591, -9307977, 4776783, -1388338, 11606556, 4162662}}},
{{{9974315, -6003765, 27132502, -1597612, -7244059, -5051030, -10580956, -7716134, -27385290, -9090921}}, {{31961548, -5303401, 2627454, 13374396, -15018324, -10769425, 21574070, -5134703, 9764589, -317547}}},
{{{-24400844, 11596617, -15999693, -2689556, -16863561, -16170634, -19780509, -650672, 18489128, -4796669}}, {{30429026, -5333539, -15012113, -8612154, 16044642, -14922026, -12060664, -4817370, -20210916, 2019944}}},
{{{-30517389, 13065383, -26538547, 4481314, -29812507, -7837046, -21950039, 12658263, -11174349, -4228508}}, {{11422, 16667282, -28495637, 9101099, 9934535, 10280997, 2230753, 87869, 16505559, -5877436}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{28040373, -16037526, -27235338, -575422, 14309370, -12952772, -29293846, -16403804, 2615166, -4100252}}, {{1834690, -5023293, 30030875, -3210908, -12598750, -5420478, 19098130, 7615129, 6459068, 5267432}}},
{{{-26170738, -8465725, 11540479, -3127682, -2979978, -11512674, 29069738, 10919588, 14488106, -14894504}}, {{20101068, 3413474, -17002829, -12235574, -18106644, -11548692, -33309941, -136830, 5227818, 4284788}}},
{{{-1015071, 40548, -23373259, -9289655, -27196884, 5529719, -33427667, -205147, -1032685, -128605}}, {{-14096028, 11790642, 9576229, 5858195, -24923218, -13271565, -5846949, -14070928, -4485563, 12486433}}},
{{{30197131, 6920783, -7830764, -4474258, -5104867, 14076173, -7220062, 8419109, 22063731, 14471967}}, {{-29458676, 8289178, 29353235, -15286131, -13167204, 724240, -29458891, -16124667, 5768683, -16403923}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-1302801, 10347390, 1801566, 67611, 27098111, -16027197, 2152977, 13045012, 20590620, 15790407}}, {{-2688859, 13679571, 9000514, -290442, -17545435, -15859083, 30312955, 10707792, 5104973, -5220229}}},
{{{-1813977, -5952871, -8054659, -10308043, -17376277, 7785699, 18060259, -9498156, 17246275, 11090676}}, {{-14440451, 1589564, 31009296, 9221419, -15785145, -13773031, 31363967, 3297145, -28008219, -14229154}}},
{{{-13216341, -10945743, -20274645, 933168, 31979900, -587048, 13396994, 1711795, -26823360, 9950370}}, {{27364749, 5725207, -31603478, 11186986, -17336038, -4950780, 29666476, -7094179, -26109795, -6529233}}},
{{{-16979094, -8116569, -7906438, 15421921, -17753174, -5486266, -32956174, -66032, -32875, 1189044}}, {{-28036816, -5074553, 5863645, 6163999, -17168938, -6031121, 26381833, 2536692, -27384491, 15436457}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-15710009, -8232280, -10608817, -4487804, 21627408, 2501508, -5316015, -15321270, -8334323, -8187298}}, {{7123412, 1061314, 23850599, 15447960, 12490441, -16296105, -28244873, 4262382, -18814128, 9169172}}},
{{{-29425630, -7978710, -1692501, 7298140, -31121532, 5445272, 22266109, 16250453, -33083722, -14666234}}, {{20124561, -6215117, 32302027, -10347683, 5946463, -6729024, 29601189, 7778254, 30850468, -11226052}}},
{{{-14722839, 13623616, 3761042, -13940345, 33056215, 16277268, 7243006, -11292907, 18396573, 4981955}}, {{17004287, 6443761, -14676461, 11330435, -31176857, -113061, -18026888, 15246699, -5055734, 10946708}}},
{{{-522696, -14636285, -33197319, -12075259, 2208431, 9463424, -23888989, 10370822, 2401980, 14563938}}, {{15643790, 9434414, 22807414, -6051352, -29718367, 8098501, -21548929, -5884146, -8333790, 4524114}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{14198878, 6088385, 29071673, 5634968, -144344, -6545639, 14898473, -5984130, 18496192, 9439052}}, {{8315744, -15230834, -26904723, -12575317, 11520786, -13499558, 18916685, -3974093, -13334325, -7026540}}},
{{{-22159877, -12934385, 11949695, -9464929, -4784592, -15987534, 16291326, 14485760, -25632718, -3516107}}, {{3869128, -11947432, -6402166, -2290011, 1247385, 7750707, 14516510, 4294722, -31691918, 3855028}}},
{{{-1604222, 1701820, -11010170, -2892029, 28135594, -8035747, 752721, -13877871, -17082004, -13300552}}, {{3355004, -13371085, 15736814, 13011898, -27416665, -14647399, -7434580, -16457462, 357213, 3180313}}},
{{{-23359771, -1863489, 14217724, 5580748, -25951805, -1261790, 1585452, 10596747, 11918771, -9797206}}, {{24926420, 7817219, 19653826, 12892636, -7458847, 14824160, 20180094, -3738434, -3225902, -1802082}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-20911664, 13723007, 27144900, 10562505, 5309240, 3550276, -13505368, -9775381, -17139228, 3862056}}, {{-19103794, -14634237, -30473916, 7055172, 3981318, -11791961, -1336208, -14745163, 1317, 3767790}}},
{{{15106853, 10510053, 30790198, -14792664, -10177117, 1648009, 11579541, 2274020, 6968154, 3836705}}, {{-15924453, -3746141, -18986637, 16378249, 21135564, -4319174, 12275850, 2324312, -13127585, 15600289}}},
{{{24852154, -12932517, -10968509, -3144560, -13474193, 15270487, -14675120, -15167091, -24954784, 8392606}}, {{33512291, 8154282, -23466210, -1749727, -28239832, 877909, 12136398, 11729988, 15209178, -1737429}}},
{{{-27500720, -2134219, 27607503, 2238739, -8974310, -3758393, -19487508, -3002130, 30831521, -10980176}}, {{-9143554, -9128652, -31734979, -14973217, 28809637, -3347220, -4908667, 5077903, 19257186, 11972646}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-15264477, 11990267, -33543230, -10134384, -21808891, -11854866, -1188329, 13708483, 31767252, 5254588}}, {{-20984284, 744942, 31654985, 5434650, 4833985, 14111806, -6977684, -1410171, 26791088, -15648051}}},
{{{-10390009, 7117188, 1034020, -12439706, 10913289, -13286350, -13586678, -6722932, 2060024, 2785085}}, {{14350832, 12169441, -29060111, -3478345, -30318147, -7121214, 29154006, 7674439, -5320345, -3359020}}},
{{{26587531, -11262791, 26133031, -14520411, -6763763, -13828372, -8854972, 9353355, 5597090, 5040490}}, {{11277856, -6942065, -1521839, 9771876, -7283271, 15309975, -6245586, -12616563, -10465080, -830060}}},
{{{14795048, -221995, -13725992, -14624567, 18522856, -822427, -32191044, -13055121, -4012343, 4116450}}, {{15324663, -9562275, -32070971, 2893282, -13977661, -4446189, 24996431, -230192, -20882900, 4248401}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-28921484, -11779153, -1209099, -12661068, 31735317, -9648108, -30560360, -16275788, -27821980, -1201834}}, {{-29708077, 13031450, -16458200, 7883979, 5409974, -2390671, -23889033, 7556155, -23008569, 3333812}}},
{{{-1706895, -3931258, -1540876, -10296517, 5477679, 12571201, 686756, 3722806, -16045034, -9746078}}, {{-15287744, -14343038, 23730108, 1310281, 25618433, -12322579, 8190711, 1461256, -19089365, -6873640}}},
{{{17676947, 6934530, -24316729, -838670, 22015323, 4637816, -30116108, -15085586, -30610945, -11705965}}, {{-22429208, 5660401, 8144484, -10396774, -30997321, -1960644, 21749867, 13500337, -6589645, 2499343}}},
{{{5682896, 15439628, 8949430, -9270243, -4353018, -1673658, -33107589, -16293157, -16833802, 16539865}}, {{-2084848, -10287193, 22356761, -5677402, 2774745, 16481951, 29652962, -7838609, 15782655, -9178648}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-2436467, 11899186, -5973137, -15875860, 32143228, 8263549, -25027698, -3177038, 31687046, 7282364}}, {{3229766, 12424768, 14809438, 9640153, 7604728, -10633143, -8928323, -1708212, 25515618, -7904217}}},
{{{164692, 6611078, 16384243, -5323051, -3413466, -4676646, 1748278, -13796795, 6261798, 1766281}}, {{10731621, -14330782, -15559968, 5795652, -16046842, 7686233, 23500680, -4974299, 30265591, 16030306}}},
{{{-14064062, -10338041, 31313880, 7716587, 3326908, 8387764, -31628063, 12446856, 11203652, -2517438}}, {{-9417548, 15205267, 8547856, -3816067, 26511461, -16600055, -261336, 11065795, -3863132, -12892630}}},
{{{1496311, -10136677, -31331404, -880291, -7024268, -5970383, -25560674, -11198201, -18130427, 2631374}}, {{-10561242, 12239849, -10215820, -14245446, 1784444, 15553341, -9071145, 2180247, 23132721, 15372799}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{2924507, -5458497, -11909692, -9684940, 11389465, 7835757, 22716835, -5497073, 28707096, 1997429}}, {{13076375, 5113601, 15402784, -1762258, 26214804, 12558885, -10139096, -12016091, 18686529, 5850277}}},
{{{14109280, -15344538, -17731658, -320022, 19318304, -8642411, -30622104, -814535, -32654065, -15043546}}, {{9730251, 13728036, -19185962, 11248320, 20844515, 12437817, 11264324, 4490212, 8357507, 2980999}}},
{{{6829610, -1206273, -4426582, 96549, -12745137, -1242375, -32248335, 4358622, -31922701, 5834123}}, {{-33480299, -6888076, -13047070, -12211434, -5224663, -16365899, 33526586, -3167009, 23799295, 2141173}}},
{{{-25729115, -12588970, -32327495, 5363488, 20337448, -12747106, 5977949, 1350102, -23488365, -10205512}}, {{26560758, -2630680, -32017225, 9494530, 9919019, -5104858, -21685369, -2900351, 3318132, 1633097}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{26450226, 14460596, -6105794, 15361446, -20229145, -2909595, 30536195, -2530418, -625288, 4377620}}, {{27544505, 5993515, 32932972, -11187803, -9981545, -8002710, 7595623, 2634614, -32534068, 5169131}}},
{{{8977668, 7602959, 32123457, 6342706, -8720625, 3392897, -394018, 14395075, 29265388, 7202166}}, {{29231736, 2840020, -31387862, 11025628, -21238210, -4573108, -15390232, 1573841, 28734917, -5103656}}},
{{{-21888926, 12277082, 3259817, -7290057, -30027693, -13231362, 28185352, -8490703, -28360917, -3934819}}, {{19549968, -880976, 26935314, -8701017, 10715528, 16029392, 29421348, -10772996, -9488421, -6907561}}},
{{{12962814, 812124, 16888418, -15237498, -32915550, -12752412, 10010569, -7953188, -21826396, -8754413}}, {{28646334, -5190919, -32111326, 8336287, -17577583, 14804197, -6706867, 7968678, -5722400, -12485628}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-32646154, -13807799, -33149277, -3206128, -22640417, -6680187, 11131524, 1388305, -15068557, 12153148}}, {{-11272034, 16192383, 434937, 6668282, -7263238, 5151055, -22398380, 7523212, -10137302, -9413435}}},
{{{-1104671, -220769, -6484254, -3916821, -20988747, 7507187, -19171945, 3000683, 15246575, -13520280}}, {{-24712667, -2886543, -7010345, 734315, -15223658, 12125517, -13079700, -15708552, 32397855, 10180036}}},
{{{-3969695, -12020758, -2865975, -4212556, -31755888, 7416322, 26848796, -1697320, 18010016, -3528250}}, {{607391, 4781386, 10383865, 14037548, -11797126, -7120952, -21700398, -12456868, 26412494, -13392523}}},
{{{-11501915, -13247350, -20104510, 2206733, -30615982, 6466157, -24234173, 7183971, 28729339, -10064248}}, {{6662626, 9711906, 29849471, 664315, -11378904, -3279138, -876640, -8033037, -11471255, 2086509}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{2578929, 5682934, -26195006, 15202760, 16776116, -12626844, -20911936, 11320830, -31466308, 4666884}}, {{2284531, 8386954, -24628308, -13510295, -3703671, -1474251, 522019, -732813, 4161268, -15743899}}},
{{{16839662, 3642408, 6305496, 6939751, -20756283, 15584601, -4381432, -13291490, 26161954, 1716431}}, {{-11567669, 11930688, -7919774, 6801457, 29676753, -7072075, 16215988, -4940862, -10930046, 4246181}}},
{{{-4406276, 12523295, 33111862, -2762967, 26389549, -10784968, -26392154, -5653107, -4236796, -14606613}}, {{-12206989, 15239368, 13553159, 8178879, 27087325, 15178288, -10032333, -8091098, 18129955, -409608}}},
{{{11649159, -14948100, 22360674, 15170448, 13997817, 5139111, 26271638, 15072516, 8645753, 8040543}}, {{19001211, -5042119, -4531324, -1846082, 32119254, 7232037, -30870850, 4940648, -33523288, 1074822}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-5863255, 12116971, -2160345, -11060824, 17038026, 5731366, 15366950, -9717293, 23491320, -12873365}}, {{28541551, -7776913, 9596255, -1167339, 11453810, 16514907, 8453163, 14209544, -1770805, -4127072}}},
{{{10222299, -3607285, 7423373, -13616285, -16171743, 5493252, -17394672, -14094803, 18964843, 13411056}}, {{-17121223, 13431679, -19728152, 9215196, -15225398, -11770087, -17139703, -6926723, -26467914, 11468029}}},
{{{26011270, -13453369, -10544448, -7199206, -25828454, 16291628, 5907092, -8038108, 18523769, 12414740}}, {{-24768726, 15168981, -20305768, -6084204, -26868513, -10340537, -21862409, -12054956, -10439480, -10752854}}},
{{{9479987, -2363169, 15996067, -11486317, 5344764, -4071805, 18912953, 4091718, -22183235, 14228121}}, {{7064748, 15613535, -32800495, -6521873, -9927766, -16725369, -21375260, -12772054, 3276203, 9663512}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-27151716, -11885053, 20830965, 5975397, -7833557, -8004417, -11663443, 10914549, -4278150, 15741050}}, {{-8078014, 2966361, -3572204, -5884771, -208279, 3086708, -31282633, 12988998, -13692089, -2908005}}},
{{{26240797, -15531237, -4401126, 11203902, 23279153, -6155877, 30975454, 10977416, -1949995, -11614408}}, {{24509208, 2867325, -7664057, -6207448, -24535575, 7229449, -21391896, 1873691, 5953891, -9266307}}},
{{{1738784, 3612580, 33046491, -9225495, -4932192, -12364432, -24493136, 12216391, 20798183, -2594281}}, {{-23017337, -9684900, -24556202, -1610870, 856922, 6048357, -25525714, 14026725, -14105119, 8591179}}},
{{{-4029544, 1075214, -1341163, -2734597, 23560340, -606932, -12304575, -16737955, -4848162, 3055059}}, {{-7269580, 14589424, 16594822, 15225288, 4200951, -12063078, 17468858, -4604053, -5427963, -11343867}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-29764261, 8913619, 15992941, 4912144, 18818545, -13140751, 33001949, -7821107, 32990297, -4608941}}, {{30067010, -2256118, 28400455, 12702689, -19918903, -15025738, -1108342, -11293332, 31233324, 12832461}}},
{{{-102561, -2587877, 32385307, -3396209, 9680642, 9636017, 8111931, -2264633, -17561584, -14314941}}, {{31098973, -15653328, -9844120, 9816671, 2307452, -9048316, -23242508, -10534659, -14174627, -159678}}},
{{{-1015472, 4146619, -7231893, -16262956, -4577103, -13386863, -9133385, 3191602, 5369998, -15018041}}, {{-12326940, 13625363, -17350459, -13505167, -18680004, -15633170, -11831781, -2333120, 9758625, 8596599}}},
{{{-1480736, -14305569, -33139188, 8489679, -27374734, -13104723, -12646503, 14289851, -22938784, 1929156}}, {{-20471916, 9460472, 14845604, 8516539, -10042874, -3519354, 8527822, 16079563, -12022735, -15800099}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{6927948, -14327694, -23968141, 2221898, 23655478, 2268215, -13445808, -4696422, 2520675, 4314108}}, {{-19550174, 8122874, -12421898, 369415, 32836358, 9924624, 32319106, -2600668, 32290433, 10907523}}},
{{{-29163981, -7680629, -7567674, 943195, 2119082, -1562719, -12815700, -13951406, -18603742, 16355091}}, {{-6515080, -6278486, -30367658, 14689254, 10055429, -1197375, -21484333, -15625839, -22361985, 14050466}}},
{{{525471, 10612618, -16445413, 7143154, 25923475, -12177669, -10911545, -12940767, -6220878, 8042380}}, {{26812595, 15434394, 9031188, 2997251, 22158962, 5587779, -28920128, -11758288, -32315699, -5037215}}},
{{{17255057, 6111787, -28014088, 3374622, -12925703, -9983149, 27535877, -4526707, 12019474, 13072383}}, {{33196086, -3294145, 17727726, 11436676, 18950370, -10221778, 12257484, -5971136, 27416805, 8942190}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-21145647, -5569596, -30118196, 8478060, -5240556, -10627750, -18472363, -6919803, 7771572, -5465772}}, {{-2856144, 13259882, -22061252, -8646316, -26970279, -2785236, -24473804, -8406700, -10913073, 16645157}}},
{{{-30143179, -6689277, -26999509, -15533872, 30214672, 12953683, -31880063, 7842967, 24692860, 9942491}}, {{-29935289, -16301218, 28008098, 13386267, 21680214, 11741711, 30613464, 16147670, 19879004, 6188414}}},
{{{29172637, 9748357, -14368086, 3527732, -17983144, -15716723, 2452105, 10177091, -1113016, 14037925}}, {{4300973, 5468731, -20063657, 2808437, 7242507, -4256561, 11252492, 11666168, -31709420, 10464404}}},
{{{4372799, 9366505, 33046984, 2054032, 5139134, -4345833, 24218565, 12704110, -30140441, -3792878}}, {{-29853560, -567838, -32858668, -7472340, 15171764, -7740659, -3553409, 12290154, -6429251, -1075612}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{23411706, 11319236, -28144514, 15917945, -19200546, 5811161, 30052029, 8190894, 4138750, -2397068}}, {{5113518, -16329589, 11225944, -1491467, 5474223, -14260201, 6848900, 3924323, -26886033, 9626735}}},
{{{-8362299, -15596667, 8794354, -9763420, -19156200, -13433402, 4102064, -5876024, 28787586, 16000964}}, {{8546791, -12704913, -22108473, 12757187, -21109519, -5537753, 8407758, 3889534, -16815620, -15215991}}},
{{{32226839, -9979039, -16864550, -6155735, 19992703, -15371259, 23265316, -14383187, -15367983, 1269003}}, {{10730912, -1654351, 725508, 365475, -11996948, 12288731, 20236296, 1479986, -3262445, -15325534}}},
{{{-16393134, 987251, 25199737, -14890559, -1747548, -3722540, 32144736, -6567005, 270606, -2661109}}, {{-30037184, -9362988, 9237229, -9814751, -3262209, -15257140, -957764, 2593275, 8744156, -5917947}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{6270503, 2711266, -29221902, -14486434, -24179619, -7204907, 17599793, -5319253, 30526860, -4961405}}, {{-9388658, -14106460, 15419813, -4270557, -33276796, 359004, 29471634, 15729985, 12013534, 3502713}}},
{{{-10496620, 16705672, -25101251, -9893950, 1622535, -8281811, 15178571, 3531106, -20340036, 5965142}}, {{-17739978, 13458712, -29694718, 16107129, 1494607, -9194056, 14087669, -973885, 22108337, 9408051}}},
{{{15169862, -3933818, 176747, 2446653, 12664575, -10578572, -22174411, -10478455, 13058623, -15356035}}, {{7088554, -12398415, -8046564, 12166363, 31924034, 7627648, 1820530, -15760010, 3589775, -10592757}}},
{{{-24920523, 14684910, -3897235, 14471035, 9958050, 211853, -6351414, -9514307, 28400842, -6580021}}, {{-11865961, 11905413, 15258239, 14940080, -2524747, 4777895, -720008, -6802912, 29463757, -11716366}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-1880003, 9848130, -28298882, -10051680, 29504102, 13429863, -22229129, 15706921, -11102380, -9024364}}, {{-31764630, -3400976, 6868666, -1774625, 24339256, 13153311, 24515185, 4236547, -3156621, 4350313}}},
{{{16243619, 11580940, 31095859, 469270, -7117702, -4150496, -12382919, -9231134, 26701734, 15737538}}, {{30577450, -10844447, -29502260, -1466737, 30202283, 4471351, 22345306, 1080271, -24248972, 12749545}}},
{{{23967206, 15192001, -7232834, -1683884, -28184020, -13212751, 15252558, -15571982, 31733118, -15823397}}, {{31602075, -7565462, 16963428, 3099521, 29506749, -8517505, -4365782, 10239736, -20085078, 4484499}}},
{{{-28841038, -3176942, 25269028, -16685170, -8241248, 6651394, 31983196, 1521951, -32294519, 10445038}}, {{-26034528, -15543281, 16790895, -14275426, 28320544, -1127756, -9713802, -4668214, -17359326, 11174439}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-18609237, 11155192, 13537375, 4418192, -120504, 6997347, -30898270, 13485042, 1231979, -15082674}}, {{-25941497, 11132940, -4271645, -231754, 11163399, -8412949, -30912477, 16130211, -8960827, -645237}}},
{{{27782682, 12742123, -1455839, -15782314, -20997223, 15951830, 29245287, 741234, -20913887, -2866150}}, {{-7930648, -5714199, 25125192, -7751752, 29583727, 10944695, -28851091, -6843119, -27556974, -8308786}}},
{{{3251625, 7317693, -13322448, 4052211, 23188216, -3806248, -26698032, 7984607, 7667189, -13228885}}, {{-17639383, -3949973, -5511713, 4906069, 9643956, -15731678, -32618605, 8818129, -12671295, 1144347}}},
{{{6395930, 7641786, -22763216, 3719903, 21317847, 11355812, -1800564, -9297140, -32765116, -6671002}}, {{-8840426, -7791723, -14996746, 4466763, -19444087, 1134051, -29134015, 1457448, 24912272, -1467427}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-7740638, -12012095, -23505933, -9636754, -29884834, -16295646, -15302152, 13147916, 548468, -12441834}}, {{-28059490, 6392098, -12572091, 7739656, -21549483, 9712764, 20798360, 537311, 27046582, -12375323}}},
{{{10181570, 8833246, -880377, 12900435, 21870766, 16774673, -31375645, 1048666, -5119788, 1935040}}, {{19916464, -5743584, -8354010, 3761700, 23931158, -5466263, 17307191, 10973064, 15075073, 15316036}}},
{{{-25159525, -12486952, -6883112, 6948370, -27313803, -15387509, 3052630, -7930366, -6198079, 3460224}}, {{-30017255, -16345493, -8336510, 12082008, -992946, -10836693, 33003598, -5818908, -11093594, 2957662}}},
{{{-8987610, -12681457, 24193012, -8742128, 12060175, -3773764, 20612738, 10273189, -12782263, 9853847}}, {{11633425, -1930147, -5583371, -16276370, 23414356, 5909726, 20300410, 1208585, -20340532, -6126945}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-2749147, 1165554, 18412962, 3947232, 6447694, 10277816, -23155370, -12644679, 12665637, 9591111}}, {{6134885, 69116, 21833374, -14340223, 11500330, 1054043, -24947223, 14031004, 24909243, 671612}}},
{{{-12756547, -15968464, -24754807, 2293797, 177214, -3567690, 19817999, 117044, 27298069, 1398030}}, {{-11168912, 4499192, 11697539, -13307372, -21072834, -14241894, -21963195, -8790016, 22232901, -10430682}}},
{{{-17214171, -3067145, 4914069, -13314097, 25201696, -12998828, -12431917, -9089589, -20248327, -6373859}}, {{-28530432, 12453037, 1004806, -7189928, 24411881, 4492868, 25751101, 14747455, 19552373, 3820808}}},
{{{-22105065, 11802205, 23254293, -6780132, -9957105, 12036109, -30970188, -4850453, -10463786, 3649754}}, {{-25002880, -2798067, -5542261, -2218468, -4152292, 5526804, -26323997, -13429782, 3834373, -14423497}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{27084679, 16075130, -1111812, 2964527, 20048250, -15042209, 5853562, -5008379, 21234446, 10679523}}, {{14007311, -16295074, 22451003, -3005915, -302994, 12163509, 31618022, 7235418, 377880, -11225251}}},
{{{-8658650, -575144, 16002984, -15589067, -29425523, -4853378, 12428169, -1131901, -25538073, 3875833}}, {{-12774957, -11846677, -7883202, -10745452, 7595002, -4162756, -19107919, -11538737, -17220213, 16228599}}},
{{{21912573, 10464675, 31322992, 9127974, -4194999, -4894047, -5305411, -6628410, 3801812, 6565585}}, {{4743635, -4389422, 27927316, -7241903, -24149044, 9156373, 16422941, 2865200, 22422423, -9863043}}},
{{{-24475163, -8987874, -28614326, -9253652, 6393230, 16442236, -19862031, 16039570, 17506669, 15007439}}, {{614625, -2245285, -11533181, 10894514, 28302522, 374255, 32110539, 12274223, -3771328, -13073377}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{24081385, 12037704, -16945244, -15171187, -14973013, -7345352, 15674402, -4076408, -2518924, 8093637}}, {{-29118984, 8488433, 13974684, 12109420, 30613987, 643686, 24695436, 5002457, 834585, 12127148}}},
{{{2372750, -11652141, 2182557, 5837152, -21700464, 1670693, 16561784, 2539142, -13340831, -10187543}}, {{10554144, 7030338, -2274681, -5224166, -17609845, 10288206, 17500664, 5711844, 17326365, 15939926}}},
{{{-28636201, -15866279, 5146609, -15304755, 11025456, -1858755, 30322030, -738926, 31004719, -6179944}}, {{-15244125, 11674343, -4404185, -2134475, 10045454, -5031267, -20617718, -6077024, 16858834, 3759447}}},
{{{29354541, -7400769, -3850862, 9681852, -32285084, -8432134, 22693369, -4951366, -25645303, -13759569}}, {{-17553364, 12041615, 8928257, -16102, -25325555, 5002692, -28679965, -1334140, 23353638, 5299550}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-24064575, 1945178, 11840372, -3597396, -32860632, -5148749, -4922762, -5553394, 30660943, 6861670}}, {{-1658808, -1195619, -31515641, 9912598, -4444233, -10828057, -7516339, 9625748, -2050850, -16706837}}},
{{{26629825, 13096932, 17689239, -7318452, 17368923, 15630954, 3888394, 14806182, 18506646, 9512433}}, {{24683317, -12336012, 13507183, 8980186, -33404115, 7606357, -2833637, -16706437, -24109288, 15598561}}},
{{{27109358, -14143513, 4881850, -3617515, 6688033, 13719607, -6286334, -15183521, 2775921, -13545667}}, {{-17384518, -562332, -282081, -9155429, -6759405, 15251355, 17526752, -10971163, 22287300, -9844185}}},
{{{16750130, 4508429, 18962788, -6425556, 8026563, 11507678, 8099915, -5762775, -27324295, -10435647}}, {{-7089103, -3802986, -6982723, 1055402, -9655106, 3153495, -14446057, 8387790, -11353533, -6336186}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{31000107, -13084824, -8136129, -11651886, 5000365, 14205048, -15299701, -13028044, -28658312, 6703685}}, {{10615676, 6121895, -26472535, 2232836, -28039089, -16507270, 30198338, -16677933, -17481217, -11861200}}},
{{{24348948, 10604008, -4591795, 13727433, 30651804, -6491968, 7335578, 3110881, -26368403, 2172712}}, {{22994409, -8213483, -11959236, 434547, -28746518, 12906875, -2645994, 7493926, -3822000, 2610035}}},
{{{2875891, 2195807, 27873904, -754267, -773530, -3018802, -30108032, 8921703, 17022198, 7874115}}, {{14042525, 9533856, 21151381, 3777253, -30242202, -10320857, 1366847, 12405336, 15829023, 3843284}}},
{{{7479527, -1762465, -24606132, -6844645, 18406083, 9612815, -11618188, -4837586, 33198971, 1014529}}, {{-29928171, -16136398, 31624612, 2434642, 18388515, -10814407, 9764723, 6204706, -8071097, 5657214}}},
{{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
{{{-11265, 11272918, 33495958, 11048722, 28244187, -9616631, -20437294, -15821050, 26498847, -5754324}}, {{-14925109, 13314881, -17460800, 10046663, 10750744, -1583947, 29746792, 15121808, -8959540, -8513865}}},
{{{-18774920, 1724758, -16127155, -438898, 12848336, -6894665, 15954707, -10267896, -14327748, 13780684}}, {{-17339348, 14199066, -11114707, 15113006, -22525984, -8332097, 33211309, 8158383, 27497451, 2499323}}},
{{{27324811, -16091331, 12647511, 8389590, 21257767, 13941716, -21007087, -12284016, -30503121, 1725513}}, {{10779885, -5325565, -21939154, -7449906, 14198532, -1948663, -21894976, 12407587, 30461170, -4386046}}},
{{{-11631075, 916980, -28187486, -2568231, 4437892, -662840, 1693883, -10374440, 14074208, 1408028}}, {{-12108164, 11258662, 7278474, -3613332, 572937, 14370671, 15783957, -16075982, -33314404, -12303085}}}

};


static void ge25519_mixadd2(ge25519_p3 *r, const ge25519_aff *q)
{
  fe25519 a,b,t1,t2,c,d,e,f,g,h,qt;
  fe25519_mul(&qt, &q->x, &q->y);
  fe25519_sub(&a, &r->y, &r->x); /* A = (Y1-X1)*(Y2-X2) */
  fe25519_add(&b, &r->y, &r->x); /* B = (Y1+X1)*(Y2+X2) */
  fe25519_sub(&t1, &q->y, &q->x);
  fe25519_add(&t2, &q->y, &q->x);
  fe25519_mul(&a, &a, &t1);
  fe25519_mul(&b, &b, &t2);
  fe25519_sub(&e, &b, &a); /* E = B-A */
  fe25519_add(&h, &b, &a); /* H = B+A */
  fe25519_mul(&c, &r->t, &qt); /* C = T1*k*T2 */
  fe25519_mul(&c, &c, &ge25519_ec2d);
  fe25519_add(&d, &r->z, &r->z); /* D = Z1*2 */
  fe25519_sub(&f, &d, &c); /* F = D-C */
  fe25519_add(&g, &d, &c); /* G = D+C */
  fe25519_mul(&r->x, &e, &f);
  fe25519_mul(&r->y, &h, &g);
  fe25519_mul(&r->z, &g, &f);
  fe25519_mul(&r->t, &e, &h);
}

static void p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p)
{
  fe25519_mul(&r->x, &p->x, &p->t);
  fe25519_mul(&r->y, &p->y, &p->z);
  fe25519_mul(&r->z, &p->z, &p->t);
}

static void p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p)
{
  p1p1_to_p2((ge25519_p2 *)r, p);
  fe25519_mul(&r->t, &p->x, &p->y);
}

static void add_p1p1(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q)
{
  fe25519 a, b, c, d, t;
  
  fe25519_sub(&a, &p->y, &p->x); /* A = (Y1-X1)*(Y2-X2) */
  fe25519_sub(&t, &q->y, &q->x);
  fe25519_mul(&a, &a, &t);
  fe25519_add(&b, &p->x, &p->y); /* B = (Y1+X1)*(Y2+X2) */
  fe25519_add(&t, &q->x, &q->y);
  fe25519_mul(&b, &b, &t);
  fe25519_mul(&c, &p->t, &q->t); /* C = T1*k*T2 */
  fe25519_mul(&c, &c, &ge25519_ec2d);
  fe25519_mul(&d, &p->z, &q->z); /* D = Z1*2*Z2 */
  fe25519_add(&d, &d, &d);
  fe25519_sub(&r->x, &b, &a); /* E = B-A */
  fe25519_sub(&r->t, &d, &c); /* F = D-C */
  fe25519_add(&r->z, &d, &c); /* G = D+C */
  fe25519_add(&r->y, &b, &a); /* H = B+A */
}

/* See http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd */
static void dbl_p1p1(ge25519_p1p1 *r, const ge25519_p2 *p)
{
  fe25519 a,b,c,d;
  fe25519_square(&a, &p->x);
  fe25519_square(&b, &p->y);
  fe25519_square_double(&c, &p->z);
  fe25519_neg(&d, &a);

  fe25519_add(&r->x, &p->x, &p->y);
  fe25519_square(&r->x, &r->x);
  fe25519_sub(&r->x, &r->x, &a);
  fe25519_sub(&r->x, &r->x, &b);
  fe25519_add(&r->z, &d, &b);
  fe25519_sub(&r->t, &r->z, &c);
  fe25519_sub(&r->y, &d, &b);
}

/* Constant-time version of: if(b) r = p */
static void cmov_aff(ge25519_aff *r, const ge25519_aff *p, unsigned char b)
{
  fe25519_cmov(&r->x, &p->x, b);
  fe25519_cmov(&r->y, &p->y, b);
}

static unsigned char group_c_static_equal(signed char b,signed char c)
{
  unsigned char ub = b;
  unsigned char uc = c;
  unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
  crypto_uint32 y = x; /* 0: yes; 1..255: no */
  y -= 1; /* 4294967295: yes; 0..254: no */
  y >>= 31; /* 1: yes; 0: no */
  return y;
}

static unsigned char negative(signed char b)
{
  unsigned long long x = b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
  x >>= 63; /* 1: yes; 0: no */
  return x;
}

static void choose_t_aff(ge25519_aff *t, unsigned long long pos, signed char b)
{
  fe25519 v;
  *t = ge25519_base_multiples_affine[5*pos+0];
  cmov_aff(t, &ge25519_base_multiples_affine[5*pos+1],group_c_static_equal(b,1) | group_c_static_equal(b,-1));
  cmov_aff(t, &ge25519_base_multiples_affine[5*pos+2],group_c_static_equal(b,2) | group_c_static_equal(b,-2));
  cmov_aff(t, &ge25519_base_multiples_affine[5*pos+3],group_c_static_equal(b,3) | group_c_static_equal(b,-3));
  cmov_aff(t, &ge25519_base_multiples_affine[5*pos+4],group_c_static_equal(b,-4));
  fe25519_neg(&v, &t->x);
  fe25519_cmov(&t->x, &v, negative(b));
}


static void choose_t(group_ge *t, const group_ge *pre, signed char b)
{
  fe25519 v;
  signed char j;
  unsigned char c;

  *t = pre[0];
  for(j=1;j<=16;j++)
  {
    c = group_c_static_equal(b,j) | group_c_static_equal(-b,j);
    fe25519_cmov(&t->x, &pre[j].x,c);
    fe25519_cmov(&t->y, &pre[j].y,c);
    fe25519_cmov(&t->z, &pre[j].z,c);
    fe25519_cmov(&t->t, &pre[j].t,c);
  }
  fe25519_neg(&v, &t->x);
  fe25519_cmov(&t->x, &v, negative(b));
  fe25519_neg(&v, &t->t);
  fe25519_cmov(&t->t, &v, negative(b));
}


// ==================================================================================
//                                    API FUNCTIONS
// ==================================================================================

/*
const group_ge group_ge_base = {{{133, 0, 0, 37120, 137, 0, 0, 42983, 58, 0, 7808, 5998, 12, 49152, 49039, 1015}},
                               {{65422, 65535, 65535, 5631, 65418, 65535, 65535, 47417, 65485, 65535, 12031, 41670, 65525, 32767, 42226, 8491}},
                               {{65422, 65535, 65535, 5631, 65418, 65535, 65535, 47417, 65485, 65535, 12031, 41670, 65525, 32767, 42226, 8491}}};
                               */

const group_ge group_ge_base = {{{-14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491}},
                                {{-26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886}},
                                {{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
                                {{28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980}}};

int group_ge_unpack(group_ge *r, const unsigned char x[GROUP_GE_PACKEDBYTES])
{
  fe25519 s, s2, chk, yden, ynum, yden2, xden2, isr, xdeninv, ydeninv, t;
  int ret;
  unsigned char b;

  fe25519_unpack(&s, x);

  /* s = cls.bytesToGf(s,mustBePositive=True) */
  ret = fe25519_isnegative(&s);

  /* yden     = 1-a*s^2    // 1+s^2 */
  /* ynum     = 1+a*s^2    // 1-s^2 */
  fe25519_square(&s2, &s);
  fe25519_add(&yden,&fe25519_one,&s2);
  fe25519_sub(&ynum,&fe25519_one,&s2);
  
  /* yden_sqr = yden^2 */
  /* xden_sqr = a*d*ynum^2 - yden_sqr */
  fe25519_square(&yden2, &yden);
  fe25519_square(&xden2, &ynum);
  fe25519_mul(&xden2, &xden2, &ge25519_ecd); // d*ynum^2
  fe25519_add(&xden2, &xden2, &yden2); // d*ynum2+yden2
  fe25519_neg(&xden2, &xden2); // -d*ynum2-yden2
  
  /* isr = isqrt(xden_sqr * yden_sqr) */
  fe25519_mul(&t, &xden2, &yden2);
  fe25519_invsqrt(&isr, &t);

  //Check inverse square root!
  fe25519_square(&chk, &isr);
  fe25519_mul(&chk, &chk, &t);

  ret |= !fe25519_isone(&chk);

  /* xden_inv = isr * yden */
  fe25519_mul(&xdeninv, &isr, &yden);
  
        
  /* yden_inv = xden_inv * isr * xden_sqr */
  fe25519_mul(&ydeninv, &xdeninv, &isr);
  fe25519_mul(&ydeninv, &ydeninv, &xden2);

  /* x = 2*s*xden_inv */
  fe25519_mul(&r->x, &s, &xdeninv);
  fe25519_double(&r->x, &r->x);

  /* if negative(x): x = -x */
  b = fe25519_isnegative(&r->x);
  fe25519_neg(&t, &r->x);
  fe25519_cmov(&r->x, &t, b);

        
  /* y = ynum * yden_inv */
  fe25519_mul(&r->y, &ynum, &ydeninv);

  r->z = fe25519_one;

  /* if cls.cofactor==8 and (negative(x*y) or y==0):
       raise InvalidEncodingException("x*y is invalid: %d, %d" % (x,y)) */
  fe25519_mul(&r->t, &r->x, &r->y);
  ret |= fe25519_isnegative(&r->t);
  ret |= fe25519_iszero(&r->y);


  // Zero all coordinates of point for invalid input; produce invalid point
  fe25519_cmov(&r->x, &fe25519_zero, ret);
  fe25519_cmov(&r->y, &fe25519_zero, ret);
  fe25519_cmov(&r->z, &fe25519_zero, ret);
  fe25519_cmov(&r->t, &fe25519_zero, ret);

  return -ret;
}

// Return x if x is positive, else return -x.
void fe25519_abs(fe25519* x, const fe25519* y)
{
    fe25519 negY;
    *x = *y;
    fe25519_neg(&negY, y);
    fe25519_cmov(x, &negY, fe25519_isnegative(x));
}

// Sets r to sqrt(x) or sqrt(i * x).  Returns 1 if x is a square.
int fe25519_sqrti(fe25519 *r, const fe25519 *x)
{
  int b;
  fe25519 t, corr;
  b = fe25519_invsqrti(&t, x);
  fe25519_setone(&corr);
  fe25519_cmov(&corr, &fe25519_sqrtm1, 1 - b);
  fe25519_mul(&t, &t, &corr);
  fe25519_mul(r, &t, x);
  return b;
}

// Sets r to 1/sqrt(x) or 1/sqrt(i*x).  Returns whether x was a square.
int fe25519_invsqrti(fe25519 *r, const fe25519 *x)
{
  int inCaseA, inCaseB, inCaseD;
  fe25519 den2, den3, den4, den6, chk, t, corr;
  fe25519_square(&den2, x);
  fe25519_mul(&den3, &den2, x);
  
  fe25519_square(&den4, &den2);
  fe25519_mul(&den6, &den2, &den4);
  fe25519_mul(&t, &den6, x); // r is now x^7
  
  fe25519_pow2523(&t, &t);
  fe25519_mul(&t, &t, &den3);
   
  // case       A           B            C             D
  // ---------------------------------------------------------------
  // t          1/sqrt(x)   -i/sqrt(x)   1/sqrt(i*x)   -i/sqrt(i*x)
  // chk        1           -1           -i            i
  // corr       1           i            1             i
  // ret        1           1            0             0
  fe25519_square(&chk, &t);
  fe25519_mul(&chk, &chk, x);

  inCaseA = fe25519_isone(&chk);
  inCaseD = fe25519_iseq(&chk, &fe25519_sqrtm1);
  fe25519_neg(&chk, &chk);
  inCaseB = fe25519_isone(&chk);

  fe25519_setone(&corr);
  fe25519_cmov(&corr, &fe25519_sqrtm1, inCaseB + inCaseD);
  fe25519_mul(&t, &t, &corr);
  
  *r = t;

  return inCaseA + inCaseB;
}


void group_ge_pack(unsigned char r[GROUP_GE_PACKEDBYTES], const group_ge *x)
{
  fe25519 d, u1, u2, isr, i1, i2, zinv, deninv, nx, ny, s;
  unsigned char b;

  /* u1    = mneg*(z+y)*(z-y) */
  fe25519_add(&d, &x->z, &x->y);
  fe25519_sub(&u1, &x->z, &x->y);
  fe25519_mul(&u1, &u1, &d);

  /* u2    = x*y # = t*z */
  fe25519_mul(&u2, &x->x, &x->y);

  /* isr   = isqrt(u1*u2^2) */
  fe25519_square(&isr, &u2);
  fe25519_mul(&isr, &isr, &u1);
  fe25519_invsqrt(&isr, &isr);

  /* i1    = isr*u1 # sqrt(mneg*(z+y)*(z-y))/(x*y) */
  fe25519_mul(&i1, &isr, &u1);
  
  /* i2    = isr*u2 # 1/sqrt(a*(y+z)*(y-z)) */
  fe25519_mul(&i2, &isr, &u2);

  /* z_inv = i1*i2*t # 1/z */
  fe25519_mul(&zinv, &i1, &i2);
  fe25519_mul(&zinv, &zinv, &x->t);

  /* if negative(t*z_inv):
       x,y = y*self.i,x*self.i
       den_inv = self.magic * i1 */
  fe25519_mul(&d, &zinv, &x->t);
  b = !fe25519_isnegative(&d);

  fe25519_mul(&nx, &x->y, &fe25519_sqrtm1);
  fe25519_mul(&ny, &x->x, &fe25519_sqrtm1);
  fe25519_mul(&deninv, &ge25519_magic, &i1);

  fe25519_cmov(&nx, &x->x, b);
  fe25519_cmov(&ny, &x->y, b);
  fe25519_cmov(&deninv, &i2, b);

  /* if negative(x*z_inv): y = -y */
  fe25519_mul(&d, &nx, &zinv);
  b = fe25519_isnegative(&d);
  fe25519_neg(&d, &ny);
  fe25519_cmov(&ny, &d, b);

  /* s = (z-y) * den_inv */
  fe25519_sub(&s, &x->z, &ny);
  fe25519_mul(&s, &s, &deninv);

  /* return self.gfToBytes(s,mustBePositive=True) */
  b = fe25519_isnegative(&s);
  fe25519_neg(&d, &s);
  fe25519_cmov(&s, &d, b);

  fe25519_pack(r, &s);
}

void group_ge_add(group_ge *r, const group_ge *x, const group_ge *y)
{
  ge25519_p1p1 t;
  add_p1p1(&t, x, y);
  p1p1_to_p3(r,&t);
}

void group_ge_double(group_ge *r, const group_ge *x)
{
  ge25519_p1p1 t;
  dbl_p1p1(&t, (ge25519_p2 *)x);
  p1p1_to_p3(r,&t);
}

void group_ge_negate(group_ge *r, const group_ge *x)
{
  fe25519_neg(&r->x, &x->x);
  r->y = x->y;
  r->z = x->z;
  fe25519_neg(&r->t, &x->t);
}

void group_ge_scalarmult(group_ge *r, const group_ge *x, const group_scalar *s)
{
  group_ge precomp[17],t;
  int i, j;
  signed char win5[51];

  scalar_window5(win5, s);

  //precomputation:
  precomp[0] = group_ge_neutral;
  precomp[1] = *x;
  for (i = 2; i < 16; i+=2)
  {
    group_ge_double(precomp+i,precomp+i/2);
    group_ge_add(precomp+i+1,precomp+i,precomp+1);
  }
  group_ge_double(precomp+16,precomp+8);

  
  *r = group_ge_neutral;
	for (i = 50; i >= 0; i--)
	{
		for (j = 0; j < 5; j++)
			group_ge_double(r, r); //change to not compute t all the time
    choose_t(&t, precomp, win5[i]);
		group_ge_add(r, r, &t);
  }
}

void group_ge_scalarmult_base(group_ge *r, const group_scalar *s)
{
  signed char b[85];
  int i;
  ge25519_aff t;
  scalar_window3(b,s);

  choose_t_aff((ge25519_aff *)r, 0, b[0]);
  r->z = fe25519_one;
  fe25519_mul(&r->t, &r->x, &r->y);
  for(i=1;i<85;i++)
  {
    choose_t_aff(&t, (unsigned long long) i, b[i]);
    ge25519_mixadd2(r, &t);
  }
}

void group_ge_multiscalarmult(group_ge *r, const group_ge *x, const group_scalar *s, unsigned long long xlen)
{
  //XXX: Use Strauss 
  unsigned long long i;
  group_ge t;
  *r = group_ge_neutral;
  for(i=0;i<xlen;i++)
  {
    group_ge_scalarmult(&t,x+i,s+i);
    group_ge_add(r,r,&t);
  }
}

int  group_ge_equals(const group_ge *x, const group_ge *y)
{
  fe25519 x1y2, x2y1, x1x2, y1y2;
  int r;
  
  fe25519_mul(&x1y2, &x->x, &y->y);
  fe25519_mul(&x2y1, &y->x, &x->y);

  r =  fe25519_iseq(&x1y2, &x2y1);

  fe25519_mul(&x1x2, &x->x, &y->x);
  fe25519_mul(&y1y2, &x->y, &y->y);
  
  r |=  fe25519_iseq(&x1x2, &y1y2);

  return r;
}

int  group_ge_isneutral(const group_ge *x)
{
  int r;
  group_ge t;

  // double three times for decaf8
  group_ge_double(&t, x);
  group_ge_double(&t, &t);
  group_ge_double(&t, &t);

  r = 1-fe25519_iszero(&t.x);
  r |= 1-fe25519_iseq(&t.y, &t.z);
  return 1-r;
}




void group_ge_add_publicinputs(group_ge *r, const group_ge *x, const group_ge *y)
{
  group_ge_add(r,x,y);
}

void group_ge_double_publicinputs(group_ge *r, const group_ge *x)
{
  group_ge_double(r,x);
}

void group_ge_negate_publicinputs(group_ge *r, const group_ge *x)
{
  group_ge_negate(r,x);
}

void group_ge_scalarmult_publicinputs(group_ge *r, const group_ge *x, const group_scalar *s)
{
  //XXX: Use sliding window
  group_ge_scalarmult(r, x, s);
}


void group_ge_scalarmult_base_publicinputs(group_ge *r, const group_scalar *s)
{
  //group_ge_scalarmult_publicinputs(r,&group_ge_base,s);
  group_ge_scalarmult_base(r,s);
}

void group_ge_multiscalarmult_publicinputs(group_ge *r, const group_ge *x, const group_scalar *s, unsigned long long xlen)
{
  //XXX: Use Bos-Coster (and something else for small values of xlen)
  group_ge_multiscalarmult(r,x,s,xlen);
}

int  group_ge_equals_publicinputs(const group_ge *x, const group_ge *y)
{
  return group_ge_equals(x,y);
}

int  group_ge_isneutral_publicinputs(const group_ge *x)
{
  return group_ge_isneutral(x);
}

/*
void ge_print(const group_ge *a) {
 fe25519_print(&a->x);
 fe25519_print(&a->y);
 fe25519_print(&a->z);
 fe25519_print(&a->t);
}
*/

// -- end of code based on the panda library --

void group_scalars_unpack(group_scalar r[], const unsigned char x[],
		int error_codes[], int n)
{
	for (int i=0; i<n; i++) {
		error_codes[i] = group_scalar_unpack(&r[i],
				x + i*GROUP_SCALAR_PACKEDBYTES);		
	}
}

void group_scalars_pack(unsigned char r[], const group_scalar x[], int n)
{
	for (int i=0; i<n; i++) {
		group_scalar_pack(r + i*GROUP_SCALAR_PACKEDBYTES, &x[i]);
	}
}

void fe25519s_unpack(fe25519 r[], const unsigned char x[], int n)
{
	for (int i=0; i<n; i++) {
		fe25519_unpack(&r[i], x + i*32);		
	}
}

void fe25519s_pack(unsigned char r[], const fe25519 x[], int n)
{
	for (int i=0; i<n; i++) {
		fe25519_pack(r + i*32, &x[i]);
	}
}

void group_ge_from_jacobi_quartic(group_ge *x, 
		const fe25519 *s, const fe25519 *t)
{
    ge25519_p1p1 res;
    fe25519 s2;

    fe25519_square(&s2, s);

    // Set x to 2 * s * 1/sqrt(-d-1)
    fe25519_double(&res.x, s);
    fe25519_mul(&res.x, &res.x, &ge25519_magic);

    // Set z to t
    res.z = *t;

    // Set y to 1-s^2
    fe25519_sub(&res.y, &fe25519_one, &s2);

    // Set t to 1+s^2
    fe25519_add(&res.t, &fe25519_one, &s2);
    p1p1_to_p3(x, &res);
}

// Compute the point corresponding to the scalar r0 in the
// Elligator2 encoding adapted to Ristretto.
void group_ge_elligator(group_ge *x, const fe25519 *r0)
{
    fe25519 r, rPlusD, rPlusOne, ecd2, D, N, ND, sqrt, twiddle, sgn;
    fe25519 s, t, dMinusOneSquared, rSubOne, r0i, sNeg;
    int b;

    // r := i * r0^2
    fe25519_mul(&r0i, r0, &fe25519_sqrtm1);
    fe25519_mul(&r, r0, &r0i);

    // D := -((d*r)+1) * (r + d)
    fe25519_add(&rPlusD, &ge25519_ecd, &r);
    fe25519_mul(&D, &ge25519_ecd, &r);
    fe25519_add(&D, &D, &fe25519_one);
    fe25519_mul(&D, &D, &rPlusD);
    fe25519_neg(&D, &D);

    // N := -(d^2 - 1)(r + 1)
    fe25519_square(&ecd2, &ge25519_ecd);
    fe25519_sub(&N, &ecd2, &fe25519_one);
    fe25519_neg(&N, &N); // TODO add -(d^2-1) as a constant
    fe25519_add(&rPlusOne, &r, &fe25519_one);
    fe25519_mul(&N, &N, &rPlusOne);

    // sqrt is the inverse square root of N*D or of i*N*D.  b=1 iff n1 is square.
    fe25519_mul(&ND, &N, &D);
    b = fe25519_invsqrti(&sqrt, &ND);
    fe25519_abs(&sqrt, &sqrt);

    fe25519_setone(&twiddle);
    fe25519_cmov(&twiddle, &r0i, 1 - b);
    fe25519_setone(&sgn);
    fe25519_cmov(&sgn, &fe25519_m1, 1 - b);
    fe25519_mul(&sqrt, &sqrt, &twiddle);

    // s = N * sqrt(N*D) * twiddle
    fe25519_mul(&s, &sqrt, &N);

    // t = -sgn * sqrt * s * (r-1) * (d-1)^2 - 1
    fe25519_neg(&t, &sgn);
    fe25519_mul(&t, &sqrt, &t);
    fe25519_mul(&t, &s, &t);
    fe25519_sub(&dMinusOneSquared, &ge25519_ecd, &fe25519_one);
    fe25519_square(&dMinusOneSquared, &dMinusOneSquared); // TODO make constant
    fe25519_mul(&t, &dMinusOneSquared, &t);
    fe25519_sub(&rSubOne, &r, &fe25519_one);
    fe25519_mul(&t, &rSubOne, &t);
    fe25519_sub(&t, &t, &fe25519_one);

    fe25519_neg(&sNeg, &s);
    fe25519_cmov(&s, &sNeg, fe25519_isnegative(&s) == b);

    group_ge_from_jacobi_quartic(x, &s, &t);
}

void group_ges_unpack(group_ge r[], const unsigned char x[],
		int error_codes[], int n)
{
	for (int i=0; i<n; i++) {
		error_codes[i] = group_ge_unpack(&r[i],
				x + i*GROUP_GE_PACKEDBYTES);		
	}
}

void group_ges_pack(unsigned char r[], const group_ge x[], int n)
{
	for (int i=0; i<n; i++) {
		group_ge_pack(r + i*GROUP_GE_PACKEDBYTES, &x[i]);
	}
}

void group_ges_scalarmult_base(group_ge y[], const group_scalar x[], int n)
{	
	for (int i=0; i<n; i++) {
		group_ge_scalarmult_base(&y[i], &x[i]);
	}
}

void group_ges_elligator(group_ge y[], const fe25519 x[], int n) 
{
	for(int i=0; i<n; i++) {
		group_ge_elligator(&y[i], &x[i]);
	}
}

int elgamal_triple_unpack(elgamal_triple *r, 
		const unsigned char x[ELGAMAL_TRIPLE_PACKEDBYTES])
{
	int result = 0;

	result += 1*group_ge_unpack(&r->blinding, x + 0*GROUP_GE_PACKEDBYTES);
	result += 2*group_ge_unpack(&r->core,     x + 1*GROUP_GE_PACKEDBYTES);
	result += 4*group_ge_unpack(&r->target,   x + 2*GROUP_GE_PACKEDBYTES);

	return result;
} 

void elgamal_triple_pack(unsigned char r[ELGAMAL_TRIPLE_PACKEDBYTES], 
		const elgamal_triple *x)
{
	group_ge_pack(r + 0*GROUP_GE_PACKEDBYTES, &(x->blinding));
	group_ge_pack(r + 1*GROUP_GE_PACKEDBYTES, &(x->core));
	group_ge_pack(r + 2*GROUP_GE_PACKEDBYTES, &(x->target));
}

void elgamal_triple_rsk(elgamal_triple *y, const elgamal_triple *x, 
		const group_scalar *k, const group_scalar *s,
		const group_scalar *r)
{
	group_ge blinding;
	group_ge core;
	group_ge target;

	group_scalar scalar;
	group_ge ge;

	// compute blinding
	group_scalar_invert(&scalar, k);
	group_scalar_mul(&scalar, &scalar, s);
	group_ge_scalarmult(&blinding, &(x->blinding), &scalar);

	group_ge_scalarmult_base(&ge, r);
	group_ge_add(&blinding, &blinding, &ge);

	// compute core
	group_ge_scalarmult(&core, &(x->core), s);
	group_scalar_mul(&scalar, k, r);
	group_ge_scalarmult(&ge, &(x->target), &scalar);
	group_ge_add(&core, &core, &ge);

	// compute target
	group_ge_scalarmult(&target, &(x->target), k);

	y->blinding = blinding;
	y->core = core;
	y->target = target;
}

void elgamal_triple_encrypt(elgamal_triple *y, const group_ge *x, 
		const group_ge *target, const group_scalar *r)
{
	group_ge blinding;
	group_ge core;

	group_ge_scalarmult_base(&blinding, r);
	group_ge_scalarmult(&core, target, r);
	group_ge_add(&core, &core, x);

	y->blinding = blinding;
	y->core = core;
	y->target = *target;
}

void elgamal_triple_decrypt(group_ge *y, const elgamal_triple *x,
		const group_scalar *key)
{
	group_ge_scalarmult(y, &x->blinding, key);
	group_ge_negate(y, y);
	group_ge_add(y, y, &x->core);
}

void elgamal_triples_unpack(elgamal_triple r[], const unsigned char x[],
		int error_codes[], int n)
{
	for (int i=0; i<n; i++) {
		error_codes[i] = elgamal_triple_unpack(&r[i],
				x + i*ELGAMAL_TRIPLE_PACKEDBYTES);		
	}
}

void elgamal_triples_pack(unsigned char r[], const elgamal_triple x[], int n)
{
	for (int i=0; i<n; i++) {
		elgamal_triple_pack(r + i*ELGAMAL_TRIPLE_PACKEDBYTES, &x[i]);
	}
}

void elgamal_triples_rsk(
		group_ge blinding_out[], group_ge core_out[],
		const group_ge blinding_in[], const group_ge core_in[],
		group_ge *target_out, const group_ge *target_in,
		const group_scalar *k, const group_scalar *s, 
		const group_scalar r[], int n)
{
	group_ge blinding;
	group_ge core;

	// precomputed
	group_scalar k_inv_times_s;
	group_ge tk;

	// temporary
	group_ge ge;

	// precompute
	group_scalar_invert(&k_inv_times_s, k);
	group_scalar_mul(&k_inv_times_s, &k_inv_times_s, s);

	group_ge_scalarmult(&tk, target_in, k);

	for (int i=0; i<n; i++) {
		// compute blinding
		group_ge_scalarmult(&blinding,
				&blinding_in[i], &k_inv_times_s);

		group_ge_scalarmult_base(&ge, &r[i]);
		group_ge_add(&blinding, &blinding, &ge);

		// compute core
		group_ge_scalarmult(&core, &core_in[i], s);

		// ge := (target_in * k) * r[i]
		// TODO: precompute powers of target_in * k?
		group_ge_scalarmult(&ge, &tk, &r[i]);
		group_ge_add(&core, &core, &ge);

		blinding_out[i] = blinding;
		core_out[i] = core;
	}

	*target_out = tk;
}

void elgamal_triples_encrypt(elgamal_triple y[], const group_ge x[],
		const group_ge *target, const group_scalar r[], int n)
{
	for (int i=0; i<n; i++) {
		elgamal_triple_encrypt(&y[i], &x[i], target, &r[i]);
	}
}

void elgamal_triples_decrypt(group_ge y[], const elgamal_triple x[],
		const group_scalar *key, int n)
{
	for (int i=0; i<n; i++) {
		elgamal_triple_decrypt(&y[i], &x[i], key);
	}
}

void component_public_part(group_ge y[253], const group_scalar *x)
{
	group_scalar xcopy = *x;

	for(int i=0; i<253; i++) 
	{
		group_ge_scalarmult_base(&y[i], &xcopy);
		group_scalar_square(&xcopy, &xcopy);
	}
}

/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/




#include <string.h>

//#include "sha2.h"

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x) (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x) (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x) (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* SHA-256 functions */

void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}

// -- end of C. Kolivas' sha256 implementation --

void dht_proof_create(
                unsigned char x[DHT_PROOF_PACKEDBYTES],
                const group_scalar *a,
                const unsigned char a_packed[GROUP_SCALAR_PACKEDBYTES],
                const unsigned char A_packed[GROUP_GE_PACKEDBYTES],
                const group_scalar *m, // either m or M must be non-NULL
                const group_ge *M,
                const unsigned char M_packed[GROUP_GE_PACKEDBYTES],
                const group_ge *N,
                const unsigned char N_packed[GROUP_GE_PACKEDBYTES])
{
        group_ge R_B, R_M;
	group_scalar s, r, h, tmp_scalar;

	unsigned char buff[160], digest[32];

	// compute r
	// we use buff[0:72] to store  DHTProof+a_packed+M_packed,
	memcpy(buff, "DHTProof", 8);
	memcpy(buff+8, a_packed, 32);
	memcpy(buff+40, M_packed, 32);
	sha256(buff, 72, digest);
	group_scalar_unpack(&r, digest);

	// compute R_B
	group_ge_scalarmult_base(&R_B, &r);

	// compute R_M
	if (m!=NULL) {
		group_scalar_mul(&tmp_scalar, m, &r);
		group_ge_scalarmult_base(&R_M, &tmp_scalar);
	} else {
		group_ge_scalarmult(&R_M, M, &r);
	}

	// compute h
	memcpy(buff, A_packed, 32);
	memcpy(buff+32, M_packed, 32);
	memcpy(buff+64, N_packed, 32);
	group_ge_pack(buff+96, &R_M);
	group_ge_pack(buff+128, &R_B);
	sha256(buff, 160, digest);
	group_scalar_unpack(&h, digest);

	// compute s
	group_scalar_mul(&tmp_scalar, &h, a);
	group_scalar_add(&s, &tmp_scalar, &r);

	// set result
	memcpy(x, buff+96, 64);  // R_M_packed + R_B_packed
	group_scalar_pack(x+64, &s);
}

int dht_proof_is_valid_for(
                const unsigned char x[96],
                const group_ge *A,
                const group_ge *M,
                const group_ge *N,
                const unsigned char A_packed[32],
                const unsigned char M_packed[32],
                const unsigned char N_packed[32])
{
	group_ge R_M, R_B;
	group_scalar s;

	unsigned char to_be_hashed[5*32];
	unsigned char digest[32];
	group_scalar h;

	group_ge lhs, rhs;
	
	// fill R_M, R_B and s
	if ( group_ge_unpack(&R_M, x)!=0 || group_ge_unpack(&R_B, x + 32)!=0 )
		return 0;

	group_scalar_unpack(&s, x + 64);

	// compute h
	memcpy(to_be_hashed, A_packed, 32);
	memcpy(to_be_hashed + 32, M_packed, 32);
	memcpy(to_be_hashed + 64, N_packed, 32);
	memcpy(to_be_hashed + 96, x, 64); // R_M and R_B

	sha256(to_be_hashed, 5*32, digest);
	group_scalar_unpack(&h, digest);

	// B*s == R_B + A*h ?
	group_ge_scalarmult_base(&lhs, &s);

	group_ge_scalarmult(&rhs, A, &h);
	group_ge_add(&rhs, &R_B, &rhs);

	if (!group_ge_equals(&lhs, &rhs))
		return 0;

	// M*s == R_M + N*h ?
	group_ge_scalarmult(&lhs, M, &s);
	
	group_ge_scalarmult(&rhs, N, &h);
	group_ge_add(&rhs, &R_M, &rhs);
	
	if (!group_ge_equals(&lhs, &rhs))
		return 0;

	return 1;
}

void product_proof_create(
                product_proof *y,
                const group_scalar factors_scalar[],
		const unsigned char factors_scalar_packed[],
                const unsigned char factors_packed[])
{
	int N = y->number_of_factors;

	group_scalar product_scalar, previous_product_scalar;
	group_ge product;

	unsigned char product_packed[32], previous_product_packed[32];

	if (N<2)
		return;

	product_scalar = factors_scalar[0];
	memcpy(product_packed, factors_packed, 32);

	for (int i=0; i<=N-2; i++) {
		previous_product_scalar = product_scalar;
		memcpy(previous_product_packed, product_packed, 32);

		group_scalar_mul(&product_scalar, &product_scalar, 
				&factors_scalar[i+1]);
		group_ge_scalarmult_base(&product, &product_scalar);
		group_ge_pack(product_packed, &product);

		if (i<N-2)
			memcpy(y->partial_products+32*i, product_packed, 32);

		dht_proof_create(
				y->dht_proofs+i*96, // x
				&factors_scalar[i+1], // a
				factors_scalar_packed+32*(i+1), // a_packed
				factors_packed+32*(i+1), // A_packed
				&previous_product_scalar, // m
				NULL, // M
				previous_product_packed, // M_packed
				&product, // N
				product_packed // N_packed
			);
	}

}

int product_proof_is_valid_for(
                const product_proof *y,
                const group_ge factors[],
                const unsigned char factors_packed[],
                const group_ge *product,
                const unsigned char product_packed[])
{
	int N = y->number_of_factors;

	group_ge next_partial_product, 
		 current_partial_product;

	unsigned char next_partial_product_packed[32],
			current_partial_product_packed[32];

	if (N==0)
		return group_ge_equals(product, &group_ge_base);

	if (N==1)
		return group_ge_equals(product, &factors[0]);

	current_partial_product = factors[0];
	memcpy(current_partial_product_packed, factors_packed, 32);

	for(int i=0; i<N-1; i++) {
		// set next_partial_product
		if (i<N-2) {
			memcpy(next_partial_product_packed, 
					y->partial_products+i*32, 32);
			if (0!=group_ge_unpack(&next_partial_product,
					next_partial_product_packed))
				return 0;
		} else { // i==N-2
			memcpy(next_partial_product_packed,
					product_packed, 32);
			next_partial_product = *product;
		}
		
		if(!dht_proof_is_valid_for(
				y->dht_proofs+96*i,
				&factors[i+1], // A
				&current_partial_product, // M
				&next_partial_product, // N
				factors_packed + (i+1)*32, // A_packed
				current_partial_product_packed, // M_packed
				next_partial_product_packed // N_packed
				))
			return 0;

		current_partial_product = next_partial_product;
		memcpy(current_partial_product_packed,
				next_partial_product_packed, 32);
	}

	return 1;
}

void certified_component_create(
                certified_component *y,
                const unsigned char base_powers_packed[8096],
                const group_scalar *base_scalar,
                const group_scalar *exponent)
{
	group_scalar current_power = *base_scalar;
	group_scalar component_scalar = group_scalar_one;
	group_ge component;

	// arguments for product_proof_create:
	unsigned char factors_packed[8096];
	unsigned char factors_scalar_packed[8096];
	group_scalar factors_scalar[253];

	int j = 0; // j is the index for factors_scalar

	for (int i=0; i<253; i++, group_scalar_square(
				&current_power, &current_power)) { 

		if (!scalar_tstbit(exponent, i))
			continue; // in particular, do not increment j

		factors_scalar[j] = current_power;
		group_scalar_pack(factors_scalar_packed + 32*j,
				&current_power);
		memcpy(factors_packed + 32*j, 
			base_powers_packed + 32*i, 32);

		group_scalar_mul(&component_scalar, 
				&component_scalar, &current_power);

		j++;
	}

	y->product_proof.number_of_factors = j;

	product_proof_create(&y->product_proof,
			factors_scalar, factors_scalar_packed, factors_packed);

	group_ge_scalarmult_base(&component, &component_scalar);
	group_ge_pack(y->component, &component);
}

int certified_component_is_valid_for(
                const certified_component *y,
                const unsigned char base_powers_packed[8096],
                const group_scalar *exponent)
	// TODO: have unpacked base powers as argument
{
	group_ge component;
	group_ge factors[253];
	unsigned char factors_packed[253*32];

	// set component
	if (0!=group_ge_unpack(&component, y->component))
		return 0;

	// set factors
	int j = 0; // j refers to the j-th factor
	for (int i=0; i<253; i++) {
		if(!scalar_tstbit(exponent, i))
			continue; // do not increment j

		memcpy(factors_packed+32*j, base_powers_packed+32*i, 32);
		if(0!=group_ge_unpack(&factors[j], base_powers_packed+32*i))
			return 0;

		j++;
	}
	
	return product_proof_is_valid_for(
		&y->product_proof,
		factors,
		factors_packed,
		&component, // product
		y->component); // product_packed
}
