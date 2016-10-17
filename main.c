#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#define Nb 4    // rows in matrix, CONSTANT!
#define Nk 8    // columns in key matrix, 4/6/8 for 128/192/256 bit AES
#define Nr 14   // rounds count, 10/12/14 for 128/192/256 bit AES

// %array_name%[rows_count] for single-dimension arrays
// %array_name%[rows_count][columns_count] for double-dimension arrays
const uint8_t in_state[Nb*Nb]={0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
const uint8_t in_cipher[Nb*Nb]={0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89};
const uint8_t in_key[Nb*Nk]={0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

uint8_t test[Nb*Nb]={0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

uint8_t key[Nb][Nk];
uint8_t state[Nb][Nb];
uint8_t out_16[Nb*Nb];
uint8_t out_32[Nb*Nk];
uint8_t round_keys[Nr+2][Nb*Nb];
uint8_t state_read_bytes_counter=0;

void show_state(void);
void show_key(void);
void show_out(uint8_t out[], uint8_t n);
void clear_screen(void);

void DEMO_ENCRYPT(void);
void DEMO_DECRYPT(void);
void DEMO_ROUND_KEY(void);
void DEMO_RANDOM_KEY(void);
void DEMO_STATE_STREAM_RW(void);
void DEMO_RND_16_TEST(void);
void DEMO_RND_256_TEST(void);
void DEMO_RND_256_PART_TEST(void);
void MENU_SELECTOR(void);

uint8_t get_hex_part(uint8_t hex, uint8_t n);
int8_t get_poly_power(uint16_t poly);
uint16_t poly_multiply(uint16_t p1, uint16_t p2);
uint16_t poly_divide(uint16_t p1, uint16_t p2);
uint8_t galua_multiply(uint16_t p1, uint16_t p2);

void do_random_init(void);
uint8_t get_random_byte(void);
void do_generate_random_key(uint8_t new_key[][Nk]);

void read_state(const uint8_t src[], uint8_t dest[][Nb]);
void read_key(const uint8_t src[], uint8_t dest[][Nk]);
void write_state(uint8_t src[][Nb], uint8_t dest[]);
void write_key(uint8_t src[][Nk], uint8_t dest[]);

uint8_t byte_read_state(uint8_t byte[]);
uint8_t byte_write_state(uint8_t counter, uint8_t src[][Nb]);

void fill_null_state(uint8_t src[][Nb]);

void key_expansion(uint8_t cur_key[][Nk], uint8_t round);
void do_generate_round_keys(uint8_t cur_key[][Nk], uint8_t round_keys[][Nb*Nb]);
void get_round_key(uint8_t src[][Nb*Nb], uint8_t dest[][Nb], uint8_t round);
void add_round_key(uint8_t src1[][Nb], uint8_t src2[][Nb]);

void sub_bytes(uint8_t src[][Nb]);
void shift_rows(uint8_t src[][Nb]);
void mix_columns(uint8_t src[][Nb]);
void do_block_encrypt(uint8_t info_block[][Nb], uint8_t cipher_key[][Nk]);

void inv_sub_bytes(uint8_t src[][Nb]);
void inv_shift_rows(uint8_t src[][Nb]);
void inv_mix_columns(uint8_t src[][Nb]);
void do_block_decrypt(uint8_t info_block[][Nb], uint8_t cipher_key[][Nk]);

int main(void){
    MENU_SELECTOR();
    return 0;
}

void show_state(void){
    uint8_t i, j;
    printf("\n\rState:\n\r");
    for(i=0; i<Nb; i++)
    {
        for(j=0; j<Nb; j++)
        {
            printf("%0*x", 2, state[i][j]);
            printf(" ");
        }
        printf("\n\r");
    }
    /* процедура выполняет вывод матрицы с информацией в консоль */
}
void show_key(void){
    uint8_t i, j;
    printf("\n\rKey:\n\r");
    for(i=0; i<Nb; i++)
    {
        for(j=0; j<Nk; j++)
        {
            printf("%0*x", 2, key[i][j]);
            printf(" ");
        }
        printf("\n\r");
    }
    /* процедура выполняет вывод матрицы с ключом шифрования в консоль */
}
void show_out(uint8_t out[], uint8_t n){
    uint8_t i;
    for(i=0; i<(Nb*n); i++)
        printf("%0*x", 2, out[i]);
    printf("\n\r");
    /* процедура выполняет вывод одномерного массива в консоль.
       n – количество элементов в массиве. */
}
void clear_screen(void){
    if(!system("clear"))
        system("clear");
    else
        system("cls");
    // процедура выполняет очистку экрана консоли.
}

uint8_t get_hex_part(uint8_t hex, uint8_t n){
    uint8_t result;
    switch(n){
        case 0: result=(hex&0x0F); break;
        case 1: result=(hex&0xF0)>>4; break;
        default:    result=0; break;
    }
    return result;
    /* функция возвращает значение младшей и старшей части байта.
       используется в прямой и инвертной процедурах SubBytes для получения
       значений X и Y (номера строки и номера столбца) в таблице замен.
       например, 0xAB состоит из младшей (B) и старшей (A) части.
       n – номер части. n=0 – младшая часть, n=1 – старшая часть. */
}
int8_t get_poly_power(uint16_t poly){
    const uint16_t power[16]={0x8000, 0x4000, 0x2000, 0x1000,
                              0x0800, 0x0400, 0x0200, 0x0100,
                              0x0080, 0x0040, 0x0020, 0x0010,
                              0x0008, 0x0004, 0x0002, 0x0001};
    uint8_t i=0;
    while(!(power[i]&poly)){
        i++;
        if(i==16)
            break;
    }
    return 15-i;
    /* функция возвращает степень полинома (0..15).
       если степень меньше нулевой, то возвращает значение -1.
       используется при умножении и делении полиномов.
       poly – полином, представленый положительным числом с кол-вом
              разрядов (бит) меньшим или равным 16. */
}
uint16_t poly_multiply(uint16_t p1, uint16_t p2){
    uint8_t i=0, j=0;
    uint16_t poly1=p1;
    uint16_t poly2=p2;
    while(get_poly_power(poly2)>-1){
        i=get_poly_power(poly2);
        if (j>0)
            poly1=((p1<<i)^poly1);
        else
            poly1=(p1<<i);
        i=trunc(pow(2, i));
        poly2=(poly2^i);
        j++;
    }
    return poly1;
    /* функция выполняет умножение двух полиномов друг на друга по
       правилам умножения полиномов, возвращая его результат.
       используется в функции умножения в поле Галуа. */
}
uint16_t poly_divide(uint16_t p1, uint16_t p2){
    uint16_t poly1=p1;
    uint16_t poly2=p2;
    while((get_poly_power(poly1)-get_poly_power(poly2))>-1)
        poly1=(poly1^(poly2<<(get_poly_power(poly1)-get_poly_power(poly2))));
    return poly1;
    /* функция выполняет деление полинома 1 на полином 2 по
       правилам деления полиномов, возвращая его результат.
       используется в функции умножения в поле Галуа. */
}
uint8_t galua_multiply(uint16_t p1, uint16_t p2){
    const uint16_t m=0x11B;
    return poly_divide(poly_multiply(p1, p2), m);
    /* функция выполняет умножение полиномов в поле Галуа (2^8).
       для гарантированного получения результата со степенью не более 7,
       в соответствии с правилами, используется деление на полином
       m = x^8 + x^4 + x^3 + x + 1.
       используется в прямой и обратной процедурах MixColumns. */
}

void do_random_init(void){
    srand(time(NULL));
    /* процедура выполняет инициализацию генератора псевдослучайных чисел
       значением текущего системного времени в секундах. */
}
uint8_t get_random_byte(void){
    uint8_t hi, lo;
    hi=(rand()%16)<<4;
    lo=rand()%16;
    hi=hi+lo;
    return hi;
    /* функция выполняет генерацию случайного числа,
       генерируя старшуи и младшую часть отдельно. */
}
void do_generate_random_key(uint8_t new_key[][Nk]){
    uint8_t i, j, k;
    for(k=0; k<(Nb*Nk); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        new_key[i][j]=get_random_byte();
    }
    // процедура выполняет генерацию случайного ключа
}

void read_state(const uint8_t src[], uint8_t dest[][Nb]){
    uint8_t i, j, k;
    for(k=0; k<(Nb*Nb); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        dest[i][j]=src[k];
    }
    /* процедура выполняет чтение данных из одномерного массива с длинной Nb*Nb
       в двумерный массив размерностью Nb строк на Nb столбцов.
       используется для чтения данных из одномерного массива state в двумерный. */
}
void read_key(const uint8_t src[], uint8_t dest[][Nk]){
    uint8_t i, j, k;
    for(k=0; k<(Nb*Nk); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        dest[i][j]=src[k];
    }
    /* процедура выполняет чтение данных из одномерного массива с длинной Nb*Nk
       в двумерный массив размерностью Nb строк на Nk столбцов.
       используется для чтения ключа из одномерного массива key в двумерный. */
}
void write_state(uint8_t src[][Nb], uint8_t dest[]){
    uint8_t i, j, k;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[k]=src[i][j];
        }
    /* процедура выполняет запись данных из двумерного массива размерностью Nb строк на Nb столбцов в
       одномерный массива с длинной Nb*Nb.
       используется для чтения данных из двумерного массива state в одномерный. */
}
void write_key(uint8_t src[][Nk], uint8_t dest[]){
    uint8_t i, j, k;
    for(j=0; j<Nk; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[k]=src[i][j];
        }
    /* процедура выполняет запись данных из двумерного массива размерностью Nb строк на Nk столбцов в
       одномерный массива с длинной Nb*Nk.
       используется для чтения ключа из двумерного массива key в одномерный. */
}

uint8_t byte_read_state(uint8_t byte[]){
    uint8_t i, j;
    j=trunc(state_read_bytes_counter/Nb);
    i=state_read_bytes_counter-j*Nb;
    state[i][j]=byte[state_read_bytes_counter];
    if(state_read_bytes_counter!=15)
    {
        state_read_bytes_counter++;
        return 0;
    }
    else
    {
        state_read_bytes_counter=0;
        return 1;
    }
    /* функция выполняет побайтовое чтение информации из потока,
       заполняя ей матрицу state. при полном ее заполнении возвращает значение true. */
}
uint8_t byte_write_state(uint8_t counter, uint8_t src[][Nb]){
    uint8_t i, j;
    j=trunc(counter/Nb);
    i=counter-j*Nb;
    return src[i][j];
    // функция выполняет побайтовую запись информации из state в поток.
}

void fill_null_state(uint8_t src[][Nb]){
    uint8_t i, j;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
            src[i][j]=0;
    // процедура выполняет заполнение нулями матрицы state.
}

void key_expansion(uint8_t cur_key[][Nk], uint8_t round){
    const uint8_t rcon[Nb][Nr]={{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const uint8_t sbox[16][16]={{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
    uint8_t r_key[Nb][Nk];
    uint8_t i, j, x, y;

    /* ГЕНЕРАЦИЯ НУЛЕВОЙ КОЛОНКИ */
    for(i=0; i<Nb; i++)
        r_key[i][0]=cur_key[i][Nk-1];
    // получение содержимого нулевой колонки предыдущего ключа
    x=r_key[0][0];
    for(i=0; i<(Nb-1); i++)
        r_key[i][0]=r_key[i+1][0];
    r_key[Nb-1][0]=x;
    // выполнение над ней процедуры RotWord
    for(i=0; i<Nb; i++)
    {
        x=get_hex_part(r_key[i][0], 1);
        y=get_hex_part(r_key[i][0], 0);
        r_key[i][0]=sbox[x][y];
    }
    // выполнение над ней процедуры SubBytes
    for (i=0; i<Nb; i++)
        r_key[i][0]=r_key[i][0]^cur_key[i][0];
    // выполнение над ней процедуры поэлементного XOR с нулевой колонкой предыдущего ключа
    for(i=0; i<Nb; i++)
        r_key[i][0]=r_key[i][0]^rcon[i][round];
    // выполнение над ней процедуры поэлементного XOR с соответствующей раунду колонкой RСon

    /* ГЕНЕРАЦИЯ ВТОРОЙ, ТРЕТЬЕЙ И ЧЕТВЕРТОЙ КОЛОНОК */
    for(i=0; i<Nb; i++)
        for(j=1; j<4; j++)
            r_key[i][j]=r_key[i][j-1]^cur_key[i][j];
    // выполнение над 1, 2 и 3 колонками процедуры поэлементного XOR с соответствующими колонками предыдущего ключа

    /* ГЕНЕРАЦИЯ ЧЕТВЕРТОЙ КОЛОНКИ */
    for(i=0; i<Nb; i++)
        r_key[i][4]=r_key[i][3];
    // получение содержимого третьей колонки нового ключа
    for(i=0; i<Nb; i++)
    {
        x=get_hex_part(r_key[i][4], 1);
        y=get_hex_part(r_key[i][4], 0);
        r_key[i][4]=sbox[x][y];
    }
    // выполнение над ней процедуры SubBytes
    for (i=0; i<Nb; i++)
        r_key[i][4]=r_key[i][4]^cur_key[i][4];
    // выполнение над ней процедуры поэлементного XOR с четвертой колонкой предыдущего ключа

    /* ГЕНЕРАЦИЯ ПЯТОЙ, ШЕСТОЙ И СЕДЬМОЙ КОЛОНОК */
    for(i=0; i<Nb; i++)
        for(j=5; j<Nk; j++)
            r_key[i][j]=r_key[i][j-1]^cur_key[i][j];
    // выполнение над 5, 6 и 7 колонками процедуры поэлементного XOR с соответствующими колонками предыдущего ключа

    /* ПЕРЕДАЧА РЕЗУЛЬТАТА ВО ВХОДНОЙ МАССИВ */
    for(i=0; i<Nb; i++)
        for(j=0; j<Nk; j++)
            cur_key[i][j]=r_key[i][j];
    // обмен данными между массивами
    /* процедура выполняет расширение ключа.
       используется при генерации раундовых ключей. */
}
void do_generate_round_keys(uint8_t cur_key[][Nk], uint8_t round_keys[][Nb*Nb]){
    uint8_t i, j, k;
    write_key(cur_key, out_32);
    for(j=0; j<(Nb*Nk); j++)
    {
        if(j<=15)
            round_keys[0][j]=out_32[j];
        else
            round_keys[1][j-16]=out_32[j];
    }
    i=2;
    for(k=0; k<trunc(Nr/2); k++)
    {
        key_expansion(cur_key, k);
        write_key(cur_key, out_32);
        for(j=0; j<(Nb*Nk); j++)
        {
            if(j<=(Nr+1))
                round_keys[i][j]=out_32[j];
            else
                round_keys[i+1][j-16]=out_32[j];
        }
        if(i<Nr)
            i+=2;
    }
    /* процедура выполняет расчет раундовых ключей. */
}
void get_round_key(uint8_t src[][Nb*Nb], uint8_t dest[][Nb], uint8_t round){
    uint8_t i, j, k;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[i][j]=src[round][k];
        }
    /* процедура возвращает ключ раунда из таблицы ключей в подставленный двумерный массив.
       round – номер раунда, 1, 2 ... Nr. при round = 0 возвращается исходный ключ шифрования
       (первые 16 байт ключа для AES-256). */
}
void add_round_key(uint8_t src1[][Nb], uint8_t src2[][Nb]){
    uint8_t i, j;
    for (i=0; i<Nb; i++)
        for (j=0; j<Nb; j++)
            src1[i][j]=src1[i][j]^src2[i][j];
    /* процедура выполняет поэлементный XOR двух двумерных массивов,
       возвращая результат в первый из них. */
}

void sub_bytes(uint8_t src[][Nb]){
    const uint8_t sbox[16][16]={{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
    uint8_t i, j, x, y;
    for(i=0; i<Nb; i++)
        for(j=0; j<Nb; j++)
        {
            x=get_hex_part(src[i][j], 1);
            y=get_hex_part(src[i][j], 0);
            src[i][j]=sbox[x][y];
        }
    /* процедура выполняет поэлементную замену элементов представленной матрицы
       на элементы из матрицы замен S-Box. */
}
void shift_rows(uint8_t src[][Nb]){
    uint8_t i, j, k, x;
    for(i=1; i<Nb; i++)
        for(k=0; k<i; k++)
        {
            x=src[i][0];
            for(j=0; j<Nb; j++)
                src[i][j]=src[i][j+1];
            src[i][Nb-1]=x;
        }
    /* процедура выполняет циклический сдвиг строк матрицы при кодировании. */
}
void mix_columns(uint8_t src[][Nb]){
    const uint8_t gfa[4][4]={{0x02, 0x03, 0x01, 0x01},
                             {0x01, 0x02, 0x03, 0x01},
                             {0x01, 0x01, 0x02, 0x03},
                             {0x03, 0x01, 0x01, 0x02}};
    uint8_t i, j, k, tmp;
    uint8_t col[4];
    tmp=0;
    for(j=0; j<Nb; j++)
    {
        for(i=0; i<Nb; i++)
            col[i]=src[i][j];
        for(i=0; i<Nb; i++)
        {
            for(k=0; k<Nb; k++)
                if(k==0)
                    tmp=galua_multiply(col[k], gfa[i][k]);
                else
                    tmp=tmp^galua_multiply(col[k], gfa[i][k]);
            src[i][j]=tmp;
        }
    }
    /* процедура выполняет перемешивание столбцов матрицы при кодировании, что
       эквивалентно умножению элементов матрицы на элементы поля Галуа. */
}
void do_block_encrypt(uint8_t info_block[][Nb], uint8_t cipher_key[][Nk]){
    uint8_t current_key[Nb][Nb];
    uint8_t i;
    do_generate_round_keys(cipher_key, round_keys);
    get_round_key(round_keys, current_key, 0);
    add_round_key(info_block, current_key);
    for(i=1; i<(Nr+1); i++)
    {
        sub_bytes(info_block);
        shift_rows(info_block);
        if(i!=Nr)
            mix_columns(info_block);
        get_round_key(round_keys, current_key, i);
        add_round_key(info_block, current_key);
    }
    // процедура выполняет шифрование блока информации в матрице info_block ключом cipher_key.
}

void inv_sub_bytes(uint8_t src[][Nb]){
    const uint8_t sbox[16][16]={{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
                                {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
                                {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
                                {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
                                {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
                                {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
                                {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
                                {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
                                {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
                                {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
                                {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
                                {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
                                {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
                                {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
                                {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
                                {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};
    uint8_t i, j, x, y;
    for(i=0; i<Nb; i++)
        for(j=0; j<Nb; j++)
        {
            x=get_hex_part(src[i][j], 1);
            y=get_hex_part(src[i][j], 0);
            src[i][j]=sbox[x][y];
        }
    /* процедура выполняет поэлементную замену элементов представленной матрицы
       на элементы из обратной матрицы замен Inv S-Box. */
}
void inv_shift_rows(uint8_t src[][Nb]){
    uint8_t i, j, k, x;
    for(i=1; i<Nb; i++)
        for(k=0; k<i; k++)
        {
            x=src[i][Nb-1];
            for(j=Nb-1; j>0; j--)
                src[i][j]=src[i][j-1];
            src[i][0]=x;
        }
    /* процедура выполняет циклический сдвиг строк матрицы при декодировании. */
}
void inv_mix_columns(uint8_t src[][Nb]){
    const uint8_t gfa[4][4]={{0x0E, 0x0B, 0x0D, 0x09},
                             {0x09, 0x0E, 0x0B, 0x0D},
                             {0x0D, 0x09, 0x0E, 0x0B},
                             {0x0B, 0x0D, 0x09, 0x0E}};
    uint8_t i, j, k, tmp;
    uint8_t col[4];
    tmp=0;
    for(j=0; j<Nb; j++)
    {
        for(i=0; i<Nb; i++)
            col[i]=src[i][j];
        for(i=0; i<Nb; i++)
        {
            for(k=0; k<Nb; k++)
                if(k==0)
                    tmp=galua_multiply(col[k], gfa[i][k]);
                else
                    tmp=tmp^galua_multiply(col[k], gfa[i][k]);
            src[i][j]=tmp;
        }
    }
    /* процедура выполняет перемешивание столбцов матрицы при декодировании, что
       эквивалентно умножению элементов матрицы на элементы поля Галуа. */
}
void do_block_decrypt(uint8_t info_block[][Nb], uint8_t cipher_key[][Nk]){
    uint8_t current_key[Nb][Nb];
    int8_t i;
    do_generate_round_keys(cipher_key, round_keys);
    get_round_key(round_keys, current_key, Nr);
    add_round_key(info_block, current_key);
    for(i=(Nr-1); i>-1; i--)
    {
        inv_shift_rows(info_block);
        inv_sub_bytes(info_block);
        get_round_key(round_keys, current_key, i);
        add_round_key(info_block, current_key);
        if(i!=0)
            inv_mix_columns(info_block);
    }
    // процедура выполняет расшифрование блока информации в матрице info_block ключом cipher_key.
}

void DEMO_ENCRYPT(void){
    read_key(in_key, key);
    read_state(in_state, state);
    printf("\n\rENCRYPT\n\r");
    show_state();
    write_state(state, out_16);
    printf("\n\rState = ");
    show_out(out_16, Nb);
    show_key();
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    do_block_encrypt(state, key);
    show_state();
    write_state(state, out_16);
    printf("\n\rState = ");
    show_out(out_16, Nb);
}
void DEMO_DECRYPT(void){
    read_key(in_key, key);
    read_state(in_cipher, state);
    printf("\n\rDECRYPT\n\r");
    show_state();
    write_state(state, out_16);
    printf("\n\rState = ");
    show_out(out_16, Nb);
    show_key();
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    do_block_decrypt(state, key);
    show_state();
    write_state(state, out_16);
    printf("\n\rState = ");
    show_out(out_16, Nb);
}
void DEMO_ROUND_KEY(void){
    uint8_t current_key[Nb][Nb];
    uint8_t i;
    read_key(in_key, key);
    printf("\n\rROUND KEY GENERATOR\n\r");
    show_key();
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    printf("\n\rN rounds = ");
    printf("%i", Nr);
    printf("\n\r\n\r");
    do_generate_round_keys(key, round_keys);
    for(i=0; i<(Nr+2); i++)
    {
        get_round_key(round_keys, current_key, i);
        write_state(current_key, out_16);
        printf("Round ");
        printf("%0*i", 2, i);
        printf(": ");
        show_out(out_16, Nb);
    }
}
void DEMO_RANDOM_KEY(void){
    int code;
    do_random_init();
    printf("\n\rRANDOM KEY GENERATOR\n\r");
    Start:
    do_generate_random_key(key);
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    printf("\n\rGenerate once again? (Yes = 1)\n\r\n\rYour choise: ");
    scanf("%i", &code);
    if(code==1)
        goto Start;
}
void DEMO_STATE_STREAM_RW(void){
    uint8_t i;
    printf("\n\rREADING/WRITING INFO FROM/TO STREAM\n\r");
    fill_null_state(state);
    write_state(state, out_16);
    printf("\n\rState (null)  = ");
    show_out(out_16, Nb);
    while(!byte_read_state(test));
    write_state(state, out_16);
    printf("\n\rState (read)  = ");
    show_out(out_16, Nb);
    for(i=0; i<(Nb*Nb); i++)
        out_16[i]=0;
    for(i=0; i<(Nb*Nb); i++)
        out_16[i]=byte_write_state(i, state);
    printf("\n\rState (write) = ");
    show_out(out_16, Nb);
}
void DEMO_RND_16_TEST(void){
    int mas[16];
    int i;
    int cnt=10000000;
    float tmp;
    printf("\n\rRANDOM NUMBER GENERATOR TEST (0 .. F)\n\r");
    printf("\n\rRepeats = ");
    printf("%i", cnt);
    printf("\n\r\n\r");
    for(i=0; i<16; i++)
        mas[i]=0;
    srand(time(NULL));
    for(i=0; i<cnt; i++)
        mas[rand()%16]++;
    for(i=0; i<16; i++)
    {
        printf("Character ");
        printf("%x", i);
        printf(": ");
        printf("%i", mas[i]);
        printf(", ");
        printf("%0*.*f", 2, 4, (mas[i]/(float)cnt)*100);
        printf("%s", "%");
        printf("\n\r");
    }
    tmp=0;
    for(i=0; i<16; i++)
        tmp=tmp+mas[i];
    tmp=(tmp/cnt)*100;
    printf("\n\rTotal = ");
    printf("%0*.*f", 2, 2, tmp);
    printf("%s", "%");
    printf("\n\r");
}
void DEMO_RND_256_TEST(void){
    int mas[256];
    int i;
    int cnt=10000000;
    float tmp;
    printf("\n\rRANDOM NUMBER GENERATOR TEST (00 .. FF)\n\r");
    printf("\n\rRepeats = ");
    printf("%i", cnt);
    printf("\n\r\n\r");
    for(i=0; i<256; i++)
        mas[i]=0;
    srand(time(NULL));
    for(i=0; i<cnt; i++)
        mas[rand()%256]++;
    for(i=0; i<256; i++)
    {
        printf("Character ");
        printf("%0*x", 2, i);
        printf(": ");
        printf("%i", mas[i]);
        printf(", ");
        printf("%0*.*f", 2, 4, (mas[i]/(float)cnt)*100);
        printf("%s", "%");
        printf("\n\r");
    }
    tmp=0;
    for(i=0; i<256; i++)
        tmp=tmp+mas[i];
    tmp=(tmp/cnt)*100;
    printf("\n\rTotal = ");
    printf("%0*.*f", 2, 2, tmp);
    printf("%s", "%");
    printf("\n\r");
}
void DEMO_RND_256_PART_TEST(void){
    int mas[256];
    int i;
    int cnt=10000000;
    float tmp;
    printf("\n\rRANDOM NUMBER PARTLY GENERATOR TEST (00 .. FF)\n\r");
    printf("\n\rRepeats = ");
    printf("%i", cnt);
    printf("\n\r\n\r");
    for(i=0; i<256; i++)
        mas[i]=0;
    srand(time(NULL));
    for(i=0; i<cnt; i++)
        mas[get_random_byte()]++;
    for(i=0; i<256; i++)
    {
        printf("Character ");
        printf("%0*x", 2, i);
        printf(": ");
        printf("%i", mas[i]);
        printf(", ");
        printf("%0*.*f", 2, 4, (mas[i]/(float)cnt)*100);
        printf("%s", "%");
        printf("\n\r");
    }
    tmp=0;
    for(i=0; i<256; i++)
        tmp=tmp+mas[i];
    tmp=(tmp/cnt)*100;
    printf("\n\rTotal = ");
    printf("%0*.*f", 2, 2, tmp);
    printf("%s", "%");
    printf("\n\r");
}

void MENU_SELECTOR(void){
    int code;
    printf("\n\rAES-256 TEST SHELL\n\r");
    printf("\n\rChoose the action:\n\r  1. Encrypt\n\r  2. Decrypt\n\r  3. Round key generator\n\r  4. Random key generator\n\r  5. Reading/writing info from/to stream\n\r  6. Random number generator test (0 .. F)\n\r  7. Random number generator test (00 .. FF)\n\r  8. Random number partly generator test (00 .. FF)\n\r\n\rYour choise: ");
    scanf("%i", &code);
    switch(code)
    {
        case 1: clear_screen(); DEMO_ENCRYPT(); break;
        case 2: clear_screen(); DEMO_DECRYPT(); break;
        case 3: clear_screen(); DEMO_ROUND_KEY(); break;
        case 4: clear_screen(); DEMO_RANDOM_KEY(); break;
        case 5: clear_screen(); DEMO_STATE_STREAM_RW(); break;
        case 6: clear_screen(); DEMO_RND_16_TEST(); break;
        case 7: clear_screen(); DEMO_RND_256_TEST(); break;
        case 8: clear_screen(); DEMO_RND_256_PART_TEST(); break;
        default: clear_screen(); printf("\n\rERROR IN CODE!\n\r"); break;
    }
    printf("\n\rReturn to menu? (Yes = 1)\n\r\n\rYour choise: ");
    scanf("%i", &code);
    switch(code)
    {
        case 1: clear_screen(); MENU_SELECTOR(); break;
        default: break;
    }
}



