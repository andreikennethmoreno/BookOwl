PGDMP     .                	    |            bookOwl    15.4    15.4                0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false                       0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false                       1262    16523    bookOwl    DATABASE     �   CREATE DATABASE "bookOwl" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_Philippines.1252';
    DROP DATABASE "bookOwl";
                postgres    false            �            1259    16525    mybooks    TABLE     �   CREATE TABLE public.mybooks (
    id integer NOT NULL,
    booktitle character varying(100),
    bookcoverurl character varying(200),
    bookauthor character varying(100),
    dateadded date
);
    DROP TABLE public.mybooks;
       public         heap    postgres    false            �            1259    16524    mybooks_id_seq    SEQUENCE     �   CREATE SEQUENCE public.mybooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.mybooks_id_seq;
       public          postgres    false    215                       0    0    mybooks_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.mybooks_id_seq OWNED BY public.mybooks.id;
          public          postgres    false    214            �            1259    16549    users    TABLE     �   CREATE TABLE public.users (
    id integer NOT NULL,
    gmail character varying(255) NOT NULL,
    password character varying(255) NOT NULL
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16548    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    217                       0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    216            �            1259    16560 
   usersbooks    TABLE     �   CREATE TABLE public.usersbooks (
    id integer NOT NULL,
    book_id integer NOT NULL,
    user_id integer NOT NULL,
    status character varying,
    datereviewed character varying,
    review text,
    rating integer
);
    DROP TABLE public.usersbooks;
       public         heap    postgres    false            �            1259    16559    usersbooks_id_seq    SEQUENCE     �   CREATE SEQUENCE public.usersbooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.usersbooks_id_seq;
       public          postgres    false    219                       0    0    usersbooks_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.usersbooks_id_seq OWNED BY public.usersbooks.id;
          public          postgres    false    218            o           2604    16528 
   mybooks id    DEFAULT     h   ALTER TABLE ONLY public.mybooks ALTER COLUMN id SET DEFAULT nextval('public.mybooks_id_seq'::regclass);
 9   ALTER TABLE public.mybooks ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215            p           2604    16552    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    217    216    217            q           2604    16563    usersbooks id    DEFAULT     n   ALTER TABLE ONLY public.usersbooks ALTER COLUMN id SET DEFAULT nextval('public.usersbooks_id_seq'::regclass);
 <   ALTER TABLE public.usersbooks ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    218    219    219                      0    16525    mybooks 
   TABLE DATA           U   COPY public.mybooks (id, booktitle, bookcoverurl, bookauthor, dateadded) FROM stdin;
    public          postgres    false    215   �                  0    16549    users 
   TABLE DATA           4   COPY public.users (id, gmail, password) FROM stdin;
    public          postgres    false    217   7"                 0    16560 
   usersbooks 
   TABLE DATA           `   COPY public.usersbooks (id, book_id, user_id, status, datereviewed, review, rating) FROM stdin;
    public          postgres    false    219   �"                  0    0    mybooks_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.mybooks_id_seq', 92, true);
          public          postgres    false    214                       0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 14, true);
          public          postgres    false    216                       0    0    usersbooks_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.usersbooks_id_seq', 44, true);
          public          postgres    false    218            s           2606    16534 (   mybooks mybooks_booktitle_bookauthor_key 
   CONSTRAINT     t   ALTER TABLE ONLY public.mybooks
    ADD CONSTRAINT mybooks_booktitle_bookauthor_key UNIQUE (booktitle, bookauthor);
 R   ALTER TABLE ONLY public.mybooks DROP CONSTRAINT mybooks_booktitle_bookauthor_key;
       public            postgres    false    215    215            u           2606    16532    mybooks mybooks_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.mybooks
    ADD CONSTRAINT mybooks_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.mybooks DROP CONSTRAINT mybooks_pkey;
       public            postgres    false    215            {           2606    16586    usersbooks unique_user_book 
   CONSTRAINT     b   ALTER TABLE ONLY public.usersbooks
    ADD CONSTRAINT unique_user_book UNIQUE (user_id, book_id);
 E   ALTER TABLE ONLY public.usersbooks DROP CONSTRAINT unique_user_book;
       public            postgres    false    219    219            w           2606    16558    users users_gmail_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_gmail_key UNIQUE (gmail);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_gmail_key;
       public            postgres    false    217            y           2606    16556    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    217            }           2606    16565    usersbooks usersbooks_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.usersbooks
    ADD CONSTRAINT usersbooks_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.usersbooks DROP CONSTRAINT usersbooks_pkey;
       public            postgres    false    219            ~           2606    16566 "   usersbooks usersbooks_book_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.usersbooks
    ADD CONSTRAINT usersbooks_book_id_fkey FOREIGN KEY (book_id) REFERENCES public.mybooks(id);
 L   ALTER TABLE ONLY public.usersbooks DROP CONSTRAINT usersbooks_book_id_fkey;
       public          postgres    false    219    3189    215                       2606    16571 "   usersbooks usersbooks_usersid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.usersbooks
    ADD CONSTRAINT usersbooks_usersid_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
 L   ALTER TABLE ONLY public.usersbooks DROP CONSTRAINT usersbooks_usersid_fkey;
       public          postgres    false    219    3193    217               @  x����n�@�5<�]�h*��DMHCE1M�41�0暙AJ��4�����.��;iǄ�_*��x�*X�+�1�?���(u��n7@L�#�5C���n�\Q��YdW<>MK�ٿ8+�"W���Y�!^�0Xۖ��O��B�Ԏy"���HaM�D��{�A��u��>k��*E���[թ��]�����y^��}K�ʄWXf�L��qOs[X�p�\p7����i����*��ÌE��#Y��
a�`�M@�Gx��k؀6���5�/,eR��`}�Q��<0%h���W�瑜J�f��[Χ���/�F         �   x�e���   �<�g��[f��VV�.Z��2���ul��}�6���Ѓ���9�UI�ą��Y��^.rS�L�����u�E�n�{w����4X̏� ��d#��B��������qE:��M�,��hHIţ�=GN6�����^u���� r�s������[*U

. ���A5         �   x�mα�0����)./`��FR�4�6Q��%��G�q:ӗ��"׮i��$���`$��\����̸NOԂ`"��oB�g��kw�VY�7���*���4܌�Xи��m���t��� f"�$�\>�4�y�(3Sa�����e����Ƴ�W?0�~T9�     