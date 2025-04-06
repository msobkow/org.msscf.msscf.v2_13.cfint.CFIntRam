
// Description: Java 11 in-memory RAM DbIO implementation for URLProtocol.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFInt 2.13 Internet Essentials
 *	
 *	Copyright 2020-2021 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *
 *	Manufactured by MSS Code Factory 2.12
 */

package org.msscf.msscf.v2_13.cfint.CFIntRam;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.msscf.msscf.v2_13.cflib.CFLib.*;
import org.msscf.msscf.v2_13.cfsec.CFSec.*;
import org.msscf.msscf.v2_13.cfint.CFInt.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;
import org.msscf.msscf.v2_13.cfsec.CFSecObj.*;
import org.msscf.msscf.v2_13.cfint.CFIntObj.*;

/*
 *	CFIntRamURLProtocolTable in-memory RAM DbIO implementation
 *	for URLProtocol.
 */
public class CFIntRamURLProtocolTable
	implements ICFIntURLProtocolTable
{
	private ICFIntSchema schema;
	private Map< CFIntURLProtocolPKey,
				CFIntURLProtocolBuff > dictByPKey
		= new HashMap< CFIntURLProtocolPKey,
				CFIntURLProtocolBuff >();
	private Map< CFIntURLProtocolByUNameIdxKey,
			CFIntURLProtocolBuff > dictByUNameIdx
		= new HashMap< CFIntURLProtocolByUNameIdxKey,
			CFIntURLProtocolBuff >();
	private Map< CFIntURLProtocolByIsSecureIdxKey,
				Map< CFIntURLProtocolPKey,
					CFIntURLProtocolBuff >> dictByIsSecureIdx
		= new HashMap< CFIntURLProtocolByIsSecureIdxKey,
				Map< CFIntURLProtocolPKey,
					CFIntURLProtocolBuff >>();

	public CFIntRamURLProtocolTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createURLProtocol( CFSecAuthorization Authorization,
		CFIntURLProtocolBuff Buff )
	{
		final String S_ProcName = "createURLProtocol";
		CFIntURLProtocolPKey pkey = schema.getFactoryURLProtocol().newPKey();
		pkey.setRequiredURLProtocolId( schema.nextURLProtocolIdGen() );
		Buff.setRequiredURLProtocolId( pkey.getRequiredURLProtocolId() );
		CFIntURLProtocolByUNameIdxKey keyUNameIdx = schema.getFactoryURLProtocol().newUNameIdxKey();
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFIntURLProtocolByIsSecureIdxKey keyIsSecureIdx = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		keyIsSecureIdx.setRequiredIsSecure( Buff.getRequiredIsSecure() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"URLProtocolUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		Map< CFIntURLProtocolPKey, CFIntURLProtocolBuff > subdictIsSecureIdx;
		if( dictByIsSecureIdx.containsKey( keyIsSecureIdx ) ) {
			subdictIsSecureIdx = dictByIsSecureIdx.get( keyIsSecureIdx );
		}
		else {
			subdictIsSecureIdx = new HashMap< CFIntURLProtocolPKey, CFIntURLProtocolBuff >();
			dictByIsSecureIdx.put( keyIsSecureIdx, subdictIsSecureIdx );
		}
		subdictIsSecureIdx.put( pkey, Buff );

	}

	public CFIntURLProtocolBuff readDerived( CFSecAuthorization Authorization,
		CFIntURLProtocolPKey PKey )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readDerived";
		CFIntURLProtocolPKey key = schema.getFactoryURLProtocol().newPKey();
		key.setRequiredURLProtocolId( PKey.getRequiredURLProtocolId() );
		CFIntURLProtocolBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff lockDerived( CFSecAuthorization Authorization,
		CFIntURLProtocolPKey PKey )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readDerived";
		CFIntURLProtocolPKey key = schema.getFactoryURLProtocol().newPKey();
		key.setRequiredURLProtocolId( PKey.getRequiredURLProtocolId() );
		CFIntURLProtocolBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamURLProtocol.readAllDerived";
		CFIntURLProtocolBuff[] retList = new CFIntURLProtocolBuff[ dictByPKey.values().size() ];
		Iterator< CFIntURLProtocolBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntURLProtocolBuff readDerivedByUNameIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readDerivedByUNameIdx";
		CFIntURLProtocolByUNameIdxKey key = schema.getFactoryURLProtocol().newUNameIdxKey();
		key.setRequiredName( Name );

		CFIntURLProtocolBuff buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff[] readDerivedByIsSecureIdx( CFSecAuthorization Authorization,
		boolean IsSecure )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readDerivedByIsSecureIdx";
		CFIntURLProtocolByIsSecureIdxKey key = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		key.setRequiredIsSecure( IsSecure );

		CFIntURLProtocolBuff[] recArray;
		if( dictByIsSecureIdx.containsKey( key ) ) {
			Map< CFIntURLProtocolPKey, CFIntURLProtocolBuff > subdictIsSecureIdx
				= dictByIsSecureIdx.get( key );
			recArray = new CFIntURLProtocolBuff[ subdictIsSecureIdx.size() ];
			Iterator< CFIntURLProtocolBuff > iter = subdictIsSecureIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntURLProtocolPKey, CFIntURLProtocolBuff > subdictIsSecureIdx
				= new HashMap< CFIntURLProtocolPKey, CFIntURLProtocolBuff >();
			dictByIsSecureIdx.put( key, subdictIsSecureIdx );
			recArray = new CFIntURLProtocolBuff[0];
		}
		return( recArray );
	}

	public CFIntURLProtocolBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		int URLProtocolId )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readDerivedByIdIdx() ";
		CFIntURLProtocolPKey key = schema.getFactoryURLProtocol().newPKey();
		key.setRequiredURLProtocolId( URLProtocolId );

		CFIntURLProtocolBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff readBuff( CFSecAuthorization Authorization,
		CFIntURLProtocolPKey PKey )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readBuff";
		CFIntURLProtocolBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a109" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff lockBuff( CFSecAuthorization Authorization,
		CFIntURLProtocolPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntURLProtocolBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a109" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntURLProtocolBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readAllBuff";
		CFIntURLProtocolBuff buff;
		ArrayList<CFIntURLProtocolBuff> filteredList = new ArrayList<CFIntURLProtocolBuff>();
		CFIntURLProtocolBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a109" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntURLProtocolBuff[0] ) );
	}

	public CFIntURLProtocolBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		int URLProtocolId )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readBuffByIdIdx() ";
		CFIntURLProtocolBuff buff = readDerivedByIdIdx( Authorization,
			URLProtocolId );
		if( ( buff != null ) && buff.getClassCode().equals( "a109" ) ) {
			return( (CFIntURLProtocolBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntURLProtocolBuff readBuffByUNameIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readBuffByUNameIdx() ";
		CFIntURLProtocolBuff buff = readDerivedByUNameIdx( Authorization,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a109" ) ) {
			return( (CFIntURLProtocolBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntURLProtocolBuff[] readBuffByIsSecureIdx( CFSecAuthorization Authorization,
		boolean IsSecure )
	{
		final String S_ProcName = "CFIntRamURLProtocol.readBuffByIsSecureIdx() ";
		CFIntURLProtocolBuff buff;
		ArrayList<CFIntURLProtocolBuff> filteredList = new ArrayList<CFIntURLProtocolBuff>();
		CFIntURLProtocolBuff[] buffList = readDerivedByIsSecureIdx( Authorization,
			IsSecure );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a109" ) ) {
				filteredList.add( (CFIntURLProtocolBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntURLProtocolBuff[0] ) );
	}

	public void updateURLProtocol( CFSecAuthorization Authorization,
		CFIntURLProtocolBuff Buff )
	{
		CFIntURLProtocolPKey pkey = schema.getFactoryURLProtocol().newPKey();
		pkey.setRequiredURLProtocolId( Buff.getRequiredURLProtocolId() );
		CFIntURLProtocolBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateURLProtocol",
				"Existing record not found",
				"URLProtocol",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateURLProtocol",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntURLProtocolByUNameIdxKey existingKeyUNameIdx = schema.getFactoryURLProtocol().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntURLProtocolByUNameIdxKey newKeyUNameIdx = schema.getFactoryURLProtocol().newUNameIdxKey();
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFIntURLProtocolByIsSecureIdxKey existingKeyIsSecureIdx = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		existingKeyIsSecureIdx.setRequiredIsSecure( existing.getRequiredIsSecure() );

		CFIntURLProtocolByIsSecureIdxKey newKeyIsSecureIdx = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		newKeyIsSecureIdx.setRequiredIsSecure( Buff.getRequiredIsSecure() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateURLProtocol",
					"URLProtocolUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFIntURLProtocolPKey, CFIntURLProtocolBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		subdict = dictByIsSecureIdx.get( existingKeyIsSecureIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByIsSecureIdx.containsKey( newKeyIsSecureIdx ) ) {
			subdict = dictByIsSecureIdx.get( newKeyIsSecureIdx );
		}
		else {
			subdict = new HashMap< CFIntURLProtocolPKey, CFIntURLProtocolBuff >();
			dictByIsSecureIdx.put( newKeyIsSecureIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteURLProtocol( CFSecAuthorization Authorization,
		CFIntURLProtocolBuff Buff )
	{
		final String S_ProcName = "CFIntRamURLProtocolTable.deleteURLProtocol() ";
		String classCode;
		CFIntURLProtocolPKey pkey = schema.getFactoryURLProtocol().newPKey();
		pkey.setRequiredURLProtocolId( Buff.getRequiredURLProtocolId() );
		CFIntURLProtocolBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteURLProtocol",
				pkey );
		}
		CFIntURLProtocolByUNameIdxKey keyUNameIdx = schema.getFactoryURLProtocol().newUNameIdxKey();
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntURLProtocolByIsSecureIdxKey keyIsSecureIdx = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		keyIsSecureIdx.setRequiredIsSecure( existing.getRequiredIsSecure() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntURLProtocolPKey, CFIntURLProtocolBuff > subdict;

		dictByPKey.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

		subdict = dictByIsSecureIdx.get( keyIsSecureIdx );
		subdict.remove( pkey );

	}
	public void deleteURLProtocolByIdIdx( CFSecAuthorization Authorization,
		int argURLProtocolId )
	{
		CFIntURLProtocolPKey key = schema.getFactoryURLProtocol().newPKey();
		key.setRequiredURLProtocolId( argURLProtocolId );
		deleteURLProtocolByIdIdx( Authorization, key );
	}

	public void deleteURLProtocolByIdIdx( CFSecAuthorization Authorization,
		CFIntURLProtocolPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntURLProtocolBuff cur;
		LinkedList<CFIntURLProtocolBuff> matchSet = new LinkedList<CFIntURLProtocolBuff>();
		Iterator<CFIntURLProtocolBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntURLProtocolBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableURLProtocol().readDerivedByIdIdx( Authorization,
				cur.getRequiredURLProtocolId() );
			deleteURLProtocol( Authorization, cur );
		}
	}

	public void deleteURLProtocolByUNameIdx( CFSecAuthorization Authorization,
		String argName )
	{
		CFIntURLProtocolByUNameIdxKey key = schema.getFactoryURLProtocol().newUNameIdxKey();
		key.setRequiredName( argName );
		deleteURLProtocolByUNameIdx( Authorization, key );
	}

	public void deleteURLProtocolByUNameIdx( CFSecAuthorization Authorization,
		CFIntURLProtocolByUNameIdxKey argKey )
	{
		CFIntURLProtocolBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntURLProtocolBuff> matchSet = new LinkedList<CFIntURLProtocolBuff>();
		Iterator<CFIntURLProtocolBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntURLProtocolBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableURLProtocol().readDerivedByIdIdx( Authorization,
				cur.getRequiredURLProtocolId() );
			deleteURLProtocol( Authorization, cur );
		}
	}

	public void deleteURLProtocolByIsSecureIdx( CFSecAuthorization Authorization,
		boolean argIsSecure )
	{
		CFIntURLProtocolByIsSecureIdxKey key = schema.getFactoryURLProtocol().newIsSecureIdxKey();
		key.setRequiredIsSecure( argIsSecure );
		deleteURLProtocolByIsSecureIdx( Authorization, key );
	}

	public void deleteURLProtocolByIsSecureIdx( CFSecAuthorization Authorization,
		CFIntURLProtocolByIsSecureIdxKey argKey )
	{
		CFIntURLProtocolBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntURLProtocolBuff> matchSet = new LinkedList<CFIntURLProtocolBuff>();
		Iterator<CFIntURLProtocolBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntURLProtocolBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableURLProtocol().readDerivedByIdIdx( Authorization,
				cur.getRequiredURLProtocolId() );
			deleteURLProtocol( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
