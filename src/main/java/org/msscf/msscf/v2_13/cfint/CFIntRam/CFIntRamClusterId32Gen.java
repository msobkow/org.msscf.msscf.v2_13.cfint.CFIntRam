// Description: Java 11 implementation of a Cluster 32-bit RAM Id Generator object.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2016-2025 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
 *	
 *	Copyright (C) 2016-2025 Mark Stephen Sobkow (mailto:mark.sobkow@gmail.com)
 *	
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes,
 *	or integrate it with proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.lang.reflect.*;
import java.io.*;
import java.math.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cflib.CFLib.xml.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;

/*
 *	CFIntRamClusterId32Gen RAM 32-bit Id Generator for Cluster
 */
public class CFIntRamClusterId32Gen
	implements Comparable<Object>,
		Serializable
{

	protected long requiredId;
	protected short sliceId = 0;
	protected int nextId = 1;

	public CFIntRamClusterId32Gen() {
		requiredId = CFSecClusterBuff.ID_INIT_VALUE;
		sliceId = 0;
		nextId = 1;
	}

	public int getNextId() {
		int retNext = nextId ++;
		return( retNext );
	}

	public long getRequiredId() {
		return( requiredId );
	}

	public void setRequiredId( long value ) {
		if( value < CFSecClusterBuff.ID_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredId",
				1,
				"value",
				value,
				CFSecClusterBuff.ID_MIN_VALUE );
		}
		requiredId = value;
	}

	public short getRequiredSliceId() {
		return( sliceId );
	}

	public void setRequiredSliceId( short value ) {
		sliceId = value;
	}

	public boolean equals( Object obj ) {
		if( obj == null ) {
			return( false );
		}
		else if( obj instanceof CFIntRamClusterId32Gen ) {
			CFIntRamClusterId32Gen rhs = (CFIntRamClusterId32Gen)obj;
			if( getRequiredId() != rhs.getRequiredId() ) {
				return( false );
			}
			if( getRequiredSliceId() != rhs.getRequiredSliceId() ) {
				return( false );
			}
			return( true );
		}
		else {
			return( false );
		}
	}

	public int hashCode() {
		int hashCode = 0;
		hashCode = hashCode + (int)( getRequiredId() );
		hashCode = ( hashCode * 0x10000 ) + getRequiredSliceId();
		return( hashCode & 0x7fffffff );
	}

	public int compareTo( Object obj ) {
		if( obj == null ) {
			return( -1 );
		}
		else if( obj instanceof CFIntRamClusterId32Gen ) {
			CFIntRamClusterId32Gen rhs = (CFIntRamClusterId32Gen)obj;
			if( getRequiredId() < rhs.getRequiredId() ) {
				return( -1 );
			}
			else if( getRequiredId() > rhs.getRequiredId() ) {
				return( 1 );
			}
			{
				short lhsSliceId = getRequiredSliceId();
				short rhsSliceId = rhs.getRequiredSliceId();
				if( lhsSliceId < rhsSliceId ) {
					return( -1 );
				}
				else if( lhsSliceId > rhsSliceId ) {
					return( 1 );
				}
			}
			return( 0 );
		}
		else {
			throw new CFLibUnsupportedClassException( getClass(),
				"compareTo",
				"obj",
				obj,
				"CFIntClusterId32Gen" );
		}
	}

	public String toString() {
		String ret = "<CFIntClusterId32Gen"
			+ " RequiredId=" + "\"" + Long.toString( getRequiredId() ) + "\""
			+ ", SliceId=\"" + Short.toString( getRequiredSliceId() ) + "\""
			+ ", NextId=\"" + Integer.toString( nextId ) + "\"/>";
		return( ret );
	}
}
