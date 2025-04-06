
// Description: Java 11 in-memory RAM DbIO implementation for TopDomain.

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
 *	CFIntRamTopDomainTable in-memory RAM DbIO implementation
 *	for TopDomain.
 */
public class CFIntRamTopDomainTable
	implements ICFIntTopDomainTable
{
	private ICFIntSchema schema;
	private Map< CFIntTopDomainPKey,
				CFIntTopDomainBuff > dictByPKey
		= new HashMap< CFIntTopDomainPKey,
				CFIntTopDomainBuff >();
	private Map< CFIntTopDomainByTenantIdxKey,
				Map< CFIntTopDomainPKey,
					CFIntTopDomainBuff >> dictByTenantIdx
		= new HashMap< CFIntTopDomainByTenantIdxKey,
				Map< CFIntTopDomainPKey,
					CFIntTopDomainBuff >>();
	private Map< CFIntTopDomainByTldIdxKey,
				Map< CFIntTopDomainPKey,
					CFIntTopDomainBuff >> dictByTldIdx
		= new HashMap< CFIntTopDomainByTldIdxKey,
				Map< CFIntTopDomainPKey,
					CFIntTopDomainBuff >>();
	private Map< CFIntTopDomainByNameIdxKey,
			CFIntTopDomainBuff > dictByNameIdx
		= new HashMap< CFIntTopDomainByNameIdxKey,
			CFIntTopDomainBuff >();

	public CFIntRamTopDomainTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createTopDomain( CFSecAuthorization Authorization,
		CFIntTopDomainBuff Buff )
	{
		final String S_ProcName = "createTopDomain";
		CFIntTopDomainPKey pkey = schema.getFactoryTopDomain().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextTopDomainIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntTopDomainByTenantIdxKey keyTenantIdx = schema.getFactoryTopDomain().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTopDomainByTldIdxKey keyTldIdx = schema.getFactoryTopDomain().newTldIdxKey();
		keyTldIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyTldIdx.setRequiredTldId( Buff.getRequiredTldId() );

		CFIntTopDomainByNameIdxKey keyNameIdx = schema.getFactoryTopDomain().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredTldId( Buff.getRequiredTldId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TopDomNameIdx",
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
						"Owner",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTld().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTldId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ParentTld",
						"Tld",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTldIdx;
		if( dictByTldIdx.containsKey( keyTldIdx ) ) {
			subdictTldIdx = dictByTldIdx.get( keyTldIdx );
		}
		else {
			subdictTldIdx = new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTldIdx.put( keyTldIdx, subdictTldIdx );
		}
		subdictTldIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntTopDomainBuff readDerived( CFSecAuthorization Authorization,
		CFIntTopDomainPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerived";
		CFIntTopDomainPKey key = schema.getFactoryTopDomain().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTopDomainBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff lockDerived( CFSecAuthorization Authorization,
		CFIntTopDomainPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerived";
		CFIntTopDomainPKey key = schema.getFactoryTopDomain().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTopDomainBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamTopDomain.readAllDerived";
		CFIntTopDomainBuff[] retList = new CFIntTopDomainBuff[ dictByPKey.values().size() ];
		Iterator< CFIntTopDomainBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntTopDomainBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerivedByTenantIdx";
		CFIntTopDomainByTenantIdxKey key = schema.getFactoryTopDomain().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntTopDomainBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntTopDomainBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntTopDomainBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTenantIdx
				= new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntTopDomainBuff[0];
		}
		return( recArray );
	}

	public CFIntTopDomainBuff[] readDerivedByTldIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TldId )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerivedByTldIdx";
		CFIntTopDomainByTldIdxKey key = schema.getFactoryTopDomain().newTldIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTldId( TldId );

		CFIntTopDomainBuff[] recArray;
		if( dictByTldIdx.containsKey( key ) ) {
			Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTldIdx
				= dictByTldIdx.get( key );
			recArray = new CFIntTopDomainBuff[ subdictTldIdx.size() ];
			Iterator< CFIntTopDomainBuff > iter = subdictTldIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdictTldIdx
				= new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTldIdx.put( key, subdictTldIdx );
			recArray = new CFIntTopDomainBuff[0];
		}
		return( recArray );
	}

	public CFIntTopDomainBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TldId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerivedByNameIdx";
		CFIntTopDomainByNameIdxKey key = schema.getFactoryTopDomain().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTldId( TldId );
		key.setRequiredName( Name );

		CFIntTopDomainBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTopDomain.readDerivedByIdIdx() ";
		CFIntTopDomainPKey key = schema.getFactoryTopDomain().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntTopDomainBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff readBuff( CFSecAuthorization Authorization,
		CFIntTopDomainPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopDomain.readBuff";
		CFIntTopDomainBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a107" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff lockBuff( CFSecAuthorization Authorization,
		CFIntTopDomainPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntTopDomainBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a107" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopDomainBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamTopDomain.readAllBuff";
		CFIntTopDomainBuff buff;
		ArrayList<CFIntTopDomainBuff> filteredList = new ArrayList<CFIntTopDomainBuff>();
		CFIntTopDomainBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a107" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntTopDomainBuff[0] ) );
	}

	public CFIntTopDomainBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTopDomain.readBuffByIdIdx() ";
		CFIntTopDomainBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a107" ) ) {
			return( (CFIntTopDomainBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntTopDomainBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTopDomain.readBuffByTenantIdx() ";
		CFIntTopDomainBuff buff;
		ArrayList<CFIntTopDomainBuff> filteredList = new ArrayList<CFIntTopDomainBuff>();
		CFIntTopDomainBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a107" ) ) {
				filteredList.add( (CFIntTopDomainBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntTopDomainBuff[0] ) );
	}

	public CFIntTopDomainBuff[] readBuffByTldIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TldId )
	{
		final String S_ProcName = "CFIntRamTopDomain.readBuffByTldIdx() ";
		CFIntTopDomainBuff buff;
		ArrayList<CFIntTopDomainBuff> filteredList = new ArrayList<CFIntTopDomainBuff>();
		CFIntTopDomainBuff[] buffList = readDerivedByTldIdx( Authorization,
			TenantId,
			TldId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a107" ) ) {
				filteredList.add( (CFIntTopDomainBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntTopDomainBuff[0] ) );
	}

	public CFIntTopDomainBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TldId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTopDomain.readBuffByNameIdx() ";
		CFIntTopDomainBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			TldId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a107" ) ) {
			return( (CFIntTopDomainBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateTopDomain( CFSecAuthorization Authorization,
		CFIntTopDomainBuff Buff )
	{
		CFIntTopDomainPKey pkey = schema.getFactoryTopDomain().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTopDomainBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTopDomain",
				"Existing record not found",
				"TopDomain",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTopDomain",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntTopDomainByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTopDomain().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTopDomainByTenantIdxKey newKeyTenantIdx = schema.getFactoryTopDomain().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTopDomainByTldIdxKey existingKeyTldIdx = schema.getFactoryTopDomain().newTldIdxKey();
		existingKeyTldIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyTldIdx.setRequiredTldId( existing.getRequiredTldId() );

		CFIntTopDomainByTldIdxKey newKeyTldIdx = schema.getFactoryTopDomain().newTldIdxKey();
		newKeyTldIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyTldIdx.setRequiredTldId( Buff.getRequiredTldId() );

		CFIntTopDomainByNameIdxKey existingKeyNameIdx = schema.getFactoryTopDomain().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredTldId( existing.getRequiredTldId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntTopDomainByNameIdxKey newKeyNameIdx = schema.getFactoryTopDomain().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredTldId( Buff.getRequiredTldId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTopDomain",
					"TopDomNameIdx",
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
						"updateTopDomain",
						"Owner",
						"Tenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTld().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTldId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTopDomain",
						"Container",
						"ParentTld",
						"Tld",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdict;

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
			subdict = new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTldIdx.get( existingKeyTldIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTldIdx.containsKey( newKeyTldIdx ) ) {
			subdict = dictByTldIdx.get( newKeyTldIdx );
		}
		else {
			subdict = new HashMap< CFIntTopDomainPKey, CFIntTopDomainBuff >();
			dictByTldIdx.put( newKeyTldIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteTopDomain( CFSecAuthorization Authorization,
		CFIntTopDomainBuff Buff )
	{
		final String S_ProcName = "CFIntRamTopDomainTable.deleteTopDomain() ";
		String classCode;
		CFIntTopDomainPKey pkey = schema.getFactoryTopDomain().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTopDomainBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTopDomain",
				pkey );
		}
					schema.getTableTopProject().deleteTopProjectByTopDomainIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
					schema.getTableLicense().deleteLicenseByDomainIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
		CFIntTopDomainByTenantIdxKey keyTenantIdx = schema.getFactoryTopDomain().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTopDomainByTldIdxKey keyTldIdx = schema.getFactoryTopDomain().newTldIdxKey();
		keyTldIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyTldIdx.setRequiredTldId( existing.getRequiredTldId() );

		CFIntTopDomainByNameIdxKey keyNameIdx = schema.getFactoryTopDomain().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredTldId( existing.getRequiredTldId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntTopDomainPKey, CFIntTopDomainBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByTldIdx.get( keyTldIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteTopDomainByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntTopDomainPKey key = schema.getFactoryTopDomain().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteTopDomainByIdIdx( Authorization, key );
	}

	public void deleteTopDomainByIdIdx( CFSecAuthorization Authorization,
		CFIntTopDomainPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntTopDomainBuff cur;
		LinkedList<CFIntTopDomainBuff> matchSet = new LinkedList<CFIntTopDomainBuff>();
		Iterator<CFIntTopDomainBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopDomainBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopDomain( Authorization, cur );
		}
	}

	public void deleteTopDomainByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntTopDomainByTenantIdxKey key = schema.getFactoryTopDomain().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTopDomainByTenantIdx( Authorization, key );
	}

	public void deleteTopDomainByTenantIdx( CFSecAuthorization Authorization,
		CFIntTopDomainByTenantIdxKey argKey )
	{
		CFIntTopDomainBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopDomainBuff> matchSet = new LinkedList<CFIntTopDomainBuff>();
		Iterator<CFIntTopDomainBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopDomainBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopDomain( Authorization, cur );
		}
	}

	public void deleteTopDomainByTldIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTldId )
	{
		CFIntTopDomainByTldIdxKey key = schema.getFactoryTopDomain().newTldIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTldId( argTldId );
		deleteTopDomainByTldIdx( Authorization, key );
	}

	public void deleteTopDomainByTldIdx( CFSecAuthorization Authorization,
		CFIntTopDomainByTldIdxKey argKey )
	{
		CFIntTopDomainBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopDomainBuff> matchSet = new LinkedList<CFIntTopDomainBuff>();
		Iterator<CFIntTopDomainBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopDomainBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopDomain( Authorization, cur );
		}
	}

	public void deleteTopDomainByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTldId,
		String argName )
	{
		CFIntTopDomainByNameIdxKey key = schema.getFactoryTopDomain().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTldId( argTldId );
		key.setRequiredName( argName );
		deleteTopDomainByNameIdx( Authorization, key );
	}

	public void deleteTopDomainByNameIdx( CFSecAuthorization Authorization,
		CFIntTopDomainByNameIdxKey argKey )
	{
		CFIntTopDomainBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopDomainBuff> matchSet = new LinkedList<CFIntTopDomainBuff>();
		Iterator<CFIntTopDomainBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopDomainBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopDomain( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
