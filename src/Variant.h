////////////////////////////////////////////////////////////////////////////////
// taskwarrior - a command line task list manager.
//
// Copyright 2006 - 2011, Paul Beckingham, Federico Hernandez.
// All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; either version 2 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the
//
//     Free Software Foundation, Inc.,
//     51 Franklin Street, Fifth Floor,
//     Boston, MA
//     02110-1301
//     USA
//
////////////////////////////////////////////////////////////////////////////////
#ifndef INCLUDED_VARIANT
#define INCLUDED_VARIANT
#define L10N                                           // Localization complete.

#include <string>
#include <time.h>
#include <Date.h>
#include <Duration.h>

class Variant
{
public:
  enum variant_type
  {
    v_unknown  = 1,
    v_boolean  = 2,
    v_integer  = 4,
    v_double   = 8,
    v_string   = 16,
    v_date     = 32,
    v_duration = 64
  };

  Variant ();
  Variant (const Variant&);
  Variant (const bool);
  Variant (const int);
  Variant (const double&);
  Variant (const std::string&);
  Variant (const Date&);
  Variant (const Duration&);
  Variant& operator= (const Variant&);

  bool operator&& (Variant& other);
  bool operator|| (Variant& other);

  bool operator<= (Variant& other);
  bool operator>= (Variant& other);
  bool operator== (Variant& other);
  bool operator< (Variant& other);
  bool operator> (Variant& other);
  bool operator!= (Variant& other);
  bool operator! ();

  Variant& operator- (Variant& other);
  Variant& operator+ (Variant& other);
  Variant& operator* (Variant& other);
  Variant& operator/ (Variant& other);

  void input (const std::string&);
  std::string format ();
  void cast (const variant_type);
  void promote (Variant&, Variant&);
  bool boolean ();
  std::string dump ();

public:
  variant_type _type;
  std::string _raw;
  std::string _raw_type;

  bool _bool;
  int _integer;
  double _double;
  std::string _string;
  Date _date;
  Duration _duration;
};

#endif

////////////////////////////////////////////////////////////////////////////////
