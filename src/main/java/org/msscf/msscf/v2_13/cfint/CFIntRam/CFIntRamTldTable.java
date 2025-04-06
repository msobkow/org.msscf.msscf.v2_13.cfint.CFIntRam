
// Description: Java 11 in-memory RAM DbIO implementation for Tld.

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
 *	CFIntRamTldTable in-memory RAM DbIO implementation
 *	for Tld.
 */
public class CFIntRamTldTable
	implements ICFIntTldTable
{
	private ICFIntSchema schema;
	private Map< CFIntTldPKey,
				CFIntTldBuff > dictByPKey
		= new HashMap< CFIntTldPKey,
				CFIntTldBuff >();
	private Map< CFIntTldByTenantIdxKey,
				Map< CFIntTldPKey,
					CFIntTldBuff >> dictByTenantIdx
		= new HashMap< CFIntTldByTenantIdxKey,
				Map< CFIntTldPKey,
					CFIntTldBuff >>();
	private Map< CFIntTldByNameIdxKey,
			CFIntTldBuff > dictByNameIdx
		= new HashMap< CFIntTldByNameIdxKey,
			CFIntTldBuff >();

	public CFIntRamTldTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createTld( CFSecAuthorization Authorization,
		CFIntTldBuff Buff )
	{
		final String S_ProcName = "createTld";
		CFIntTldPKey pkey = schema.getFactoryTld().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextTldIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntTldByTenantIdxKey keyTenantIdx = schema.getFactoryTld().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTldByNameIdxKey keyNameIdx = schema.getFactoryTld().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TldNameIdx",
				keyNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"TldTenant",
						"Tenant",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntTldPKey, CFIntTldBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntTldPKey, CFIntTldBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntTldBuff readDerived( CFSecAuthorization Authorization,
		CFIntTldPKey PKey )
	{
		final String S_ProcName = "CFIntRamTld.readDerived";
		CFIntTldPKey key = schema.getFactoryTld().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTldBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff lockDerived( CFSecAuthorization Authorization,
		CFIntTldPKey PKey )
	{
		final String S_ProcName = "CFIntRamTld.readDerived";
		CFIntTldPKey key = schema.getFactoryTld().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTldBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamTld.readAllDerived";
		CFIntTldBuff[] retList = new CFIntTldBuff[ dictByPKey.values().size() ];
		Iterator< CFIntTldBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntTldBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTld.readDerivedByTenantIdx";
		CFIntTldByTenantIdxKey key = schema.getFactoryTld().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntTldBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntTldPKey, CFIntTldBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntTldBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntTldBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntTldPKey, CFIntTldBuff > subdictTenantIdx
				= new HashMap< CFIntTldPKey, CFIntTldBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntTldBuff[0];
		}
		return( recArray );
	}

	public CFIntTldBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTld.readDerivedByNameIdx";
		CFIntTldByNameIdxKey key = schema.getFactoryTld().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredName( Name );

		CFIntTldBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTld.readDerivedByIdIdx() ";
		CFIntTldPKey key = schema.getFactoryTld().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntTldBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff readBuff( CFSecAuthorization Authorization,
		CFIntTldPKey PKey )
	{
		final String S_ProcName = "CFIntRamTld.readBuff";
		CFIntTldBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a106" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff lockBuff( CFSecAuthorization Authorization,
		CFIntTldPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntTldBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a106" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTldBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamTld.readAllBuff";
		CFIntTldBuff buff;
		ArrayList<CFIntTldBuff> filteredList = new ArrayList<CFIntTldBuff>();
		CFIntTldBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a106" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntTldBuff[0] ) );
	}

	public CFIntTldBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTld.readBuffByIdIdx() ";
		CFIntTldBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a106" ) ) {
			return( (CFIntTldBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntTldBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTld.readBuffByTenantIdx() ";
		CFIntTldBuff buff;
		ArrayList<CFIntTldBuff> filteredList = new ArrayList<CFIntTldBuff>();
		CFIntTldBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a106" ) ) {
				filteredList.add( (CFIntTldBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntTldBuff[0] ) );
	}

	public CFIntTldBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTld.readBuffByNameIdx() ";
		CFIntTldBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a106" ) ) {
			return( (CFIntTldBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateTld( CFSecAuthorization Authorization,
		CFIntTldBuff Buff )
	{
		CFIntTldPKey pkey = schema.getFactoryTld().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTldBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTld",
				"Existing record not found",
				"Tld",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTld",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntTldByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTld().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTldByTenantIdxKey newKeyTenantIdx = schema.getFactoryTld().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTldByNameIdxKey existingKeyNameIdx = schema.getFactoryTld().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntTldByNameIdxKey newKeyNameIdx = schema.getFactoryTld().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTld",
					"TldNameIdx",
					newKeyNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTld",
						"Container",
						"TldTenant",
						"Tenant",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntTldPKey, CFIntTldBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTenantIdx.get( existingKeyTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantIdx.containsKey( newKeyTenantIdx ) ) {
			subdict = dictByTenantIdx.get( newKeyTenantIdx );
		}
		else {
			subdict = new HashMap< CFIntTldPKey, CFIntTldBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteTld( CFSecAuthorization Authorization,
		CFIntTldBuff Buff )
	{
		final String S_ProcName = "CFIntRamTldTable.deleteTld() ";
		String classCode;
		CFIntTldPKey pkey = schema.getFactoryTld().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTldBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTld",
				pkey );
		}
					schema.getTableTopDomain().deleteTopDomainByTldIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
		CFIntTldByTenantIdxKey keyTenantIdx = schema.getFactoryTld().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTldByNameIdxKey keyNameIdx = schema.getFactoryTld().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntTldPKey, CFIntTldBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteTldByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntTldPKey key = schema.getFactoryTld().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteTldByIdIdx( Authorization, key );
	}

	public void deleteTldByIdIdx( CFSecAuthorization Authorization,
		CFIntTldPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntTldBuff cur;
		LinkedList<CFIntTldBuff> matchSet = new LinkedList<CFIntTldBuff>();
		Iterator<CFIntTldBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTldBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTld().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTld( Authorization, cur );
		}
	}

	public void deleteTldByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntTldByTenantIdxKey key = schema.getFactoryTld().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTldByTenantIdx( Authorization, key );
	}

	public void deleteTldByTenantIdx( CFSecAuthorization Authorization,
		CFIntTldByTenantIdxKey argKey )
	{
		CFIntTldBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTldBuff> matchSet = new LinkedList<CFIntTldBuff>();
		Iterator<CFIntTldBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTldBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTld().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTld( Authorization, cur );
		}
	}

	public void deleteTldByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		String argName )
	{
		CFIntTldByNameIdxKey key = schema.getFactoryTld().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredName( argName );
		deleteTldByNameIdx( Authorization, key );
	}

	public void deleteTldByNameIdx( CFSecAuthorization Authorization,
		CFIntTldByNameIdxKey argKey )
	{
		CFIntTldBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTldBuff> matchSet = new LinkedList<CFIntTldBuff>();
		Iterator<CFIntTldBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTldBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTld().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTld( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
