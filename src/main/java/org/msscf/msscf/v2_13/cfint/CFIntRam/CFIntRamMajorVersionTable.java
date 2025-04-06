
// Description: Java 11 in-memory RAM DbIO implementation for MajorVersion.

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
 *	CFIntRamMajorVersionTable in-memory RAM DbIO implementation
 *	for MajorVersion.
 */
public class CFIntRamMajorVersionTable
	implements ICFIntMajorVersionTable
{
	private ICFIntSchema schema;
	private Map< CFIntMajorVersionPKey,
				CFIntMajorVersionBuff > dictByPKey
		= new HashMap< CFIntMajorVersionPKey,
				CFIntMajorVersionBuff >();
	private Map< CFIntMajorVersionByTenantIdxKey,
				Map< CFIntMajorVersionPKey,
					CFIntMajorVersionBuff >> dictByTenantIdx
		= new HashMap< CFIntMajorVersionByTenantIdxKey,
				Map< CFIntMajorVersionPKey,
					CFIntMajorVersionBuff >>();
	private Map< CFIntMajorVersionBySubProjectIdxKey,
				Map< CFIntMajorVersionPKey,
					CFIntMajorVersionBuff >> dictBySubProjectIdx
		= new HashMap< CFIntMajorVersionBySubProjectIdxKey,
				Map< CFIntMajorVersionPKey,
					CFIntMajorVersionBuff >>();
	private Map< CFIntMajorVersionByNameIdxKey,
			CFIntMajorVersionBuff > dictByNameIdx
		= new HashMap< CFIntMajorVersionByNameIdxKey,
			CFIntMajorVersionBuff >();

	public CFIntRamMajorVersionTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createMajorVersion( CFSecAuthorization Authorization,
		CFIntMajorVersionBuff Buff )
	{
		final String S_ProcName = "createMajorVersion";
		CFIntMajorVersionPKey pkey = schema.getFactoryMajorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextMajorVersionIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntMajorVersionByTenantIdxKey keyTenantIdx = schema.getFactoryMajorVersion().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntMajorVersionBySubProjectIdxKey keySubProjectIdx = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		keySubProjectIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keySubProjectIdx.setRequiredSubProjectId( Buff.getRequiredSubProjectId() );

		CFIntMajorVersionByNameIdxKey keyNameIdx = schema.getFactoryMajorVersion().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredSubProjectId( Buff.getRequiredSubProjectId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"MajorVersionNameIdx",
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
				if( null == schema.getTableSubProject().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredSubProjectId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ParentSubProject",
						"SubProject",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictSubProjectIdx;
		if( dictBySubProjectIdx.containsKey( keySubProjectIdx ) ) {
			subdictSubProjectIdx = dictBySubProjectIdx.get( keySubProjectIdx );
		}
		else {
			subdictSubProjectIdx = new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictBySubProjectIdx.put( keySubProjectIdx, subdictSubProjectIdx );
		}
		subdictSubProjectIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntMajorVersionBuff readDerived( CFSecAuthorization Authorization,
		CFIntMajorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerived";
		CFIntMajorVersionPKey key = schema.getFactoryMajorVersion().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntMajorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff lockDerived( CFSecAuthorization Authorization,
		CFIntMajorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerived";
		CFIntMajorVersionPKey key = schema.getFactoryMajorVersion().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntMajorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamMajorVersion.readAllDerived";
		CFIntMajorVersionBuff[] retList = new CFIntMajorVersionBuff[ dictByPKey.values().size() ];
		Iterator< CFIntMajorVersionBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntMajorVersionBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerivedByTenantIdx";
		CFIntMajorVersionByTenantIdxKey key = schema.getFactoryMajorVersion().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntMajorVersionBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntMajorVersionBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntMajorVersionBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictTenantIdx
				= new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntMajorVersionBuff[0];
		}
		return( recArray );
	}

	public CFIntMajorVersionBuff[] readDerivedBySubProjectIdx( CFSecAuthorization Authorization,
		long TenantId,
		long SubProjectId )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerivedBySubProjectIdx";
		CFIntMajorVersionBySubProjectIdxKey key = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredSubProjectId( SubProjectId );

		CFIntMajorVersionBuff[] recArray;
		if( dictBySubProjectIdx.containsKey( key ) ) {
			Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictSubProjectIdx
				= dictBySubProjectIdx.get( key );
			recArray = new CFIntMajorVersionBuff[ subdictSubProjectIdx.size() ];
			Iterator< CFIntMajorVersionBuff > iter = subdictSubProjectIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdictSubProjectIdx
				= new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictBySubProjectIdx.put( key, subdictSubProjectIdx );
			recArray = new CFIntMajorVersionBuff[0];
		}
		return( recArray );
	}

	public CFIntMajorVersionBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long SubProjectId,
		String Name )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerivedByNameIdx";
		CFIntMajorVersionByNameIdxKey key = schema.getFactoryMajorVersion().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredSubProjectId( SubProjectId );
		key.setRequiredName( Name );

		CFIntMajorVersionBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readDerivedByIdIdx() ";
		CFIntMajorVersionPKey key = schema.getFactoryMajorVersion().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntMajorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff readBuff( CFSecAuthorization Authorization,
		CFIntMajorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readBuff";
		CFIntMajorVersionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a102" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff lockBuff( CFSecAuthorization Authorization,
		CFIntMajorVersionPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntMajorVersionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a102" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntMajorVersionBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readAllBuff";
		CFIntMajorVersionBuff buff;
		ArrayList<CFIntMajorVersionBuff> filteredList = new ArrayList<CFIntMajorVersionBuff>();
		CFIntMajorVersionBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a102" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntMajorVersionBuff[0] ) );
	}

	public CFIntMajorVersionBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readBuffByIdIdx() ";
		CFIntMajorVersionBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a102" ) ) {
			return( (CFIntMajorVersionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntMajorVersionBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readBuffByTenantIdx() ";
		CFIntMajorVersionBuff buff;
		ArrayList<CFIntMajorVersionBuff> filteredList = new ArrayList<CFIntMajorVersionBuff>();
		CFIntMajorVersionBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a102" ) ) {
				filteredList.add( (CFIntMajorVersionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntMajorVersionBuff[0] ) );
	}

	public CFIntMajorVersionBuff[] readBuffBySubProjectIdx( CFSecAuthorization Authorization,
		long TenantId,
		long SubProjectId )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readBuffBySubProjectIdx() ";
		CFIntMajorVersionBuff buff;
		ArrayList<CFIntMajorVersionBuff> filteredList = new ArrayList<CFIntMajorVersionBuff>();
		CFIntMajorVersionBuff[] buffList = readDerivedBySubProjectIdx( Authorization,
			TenantId,
			SubProjectId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a102" ) ) {
				filteredList.add( (CFIntMajorVersionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntMajorVersionBuff[0] ) );
	}

	public CFIntMajorVersionBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long SubProjectId,
		String Name )
	{
		final String S_ProcName = "CFIntRamMajorVersion.readBuffByNameIdx() ";
		CFIntMajorVersionBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			SubProjectId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a102" ) ) {
			return( (CFIntMajorVersionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateMajorVersion( CFSecAuthorization Authorization,
		CFIntMajorVersionBuff Buff )
	{
		CFIntMajorVersionPKey pkey = schema.getFactoryMajorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntMajorVersionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateMajorVersion",
				"Existing record not found",
				"MajorVersion",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateMajorVersion",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntMajorVersionByTenantIdxKey existingKeyTenantIdx = schema.getFactoryMajorVersion().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntMajorVersionByTenantIdxKey newKeyTenantIdx = schema.getFactoryMajorVersion().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntMajorVersionBySubProjectIdxKey existingKeySubProjectIdx = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		existingKeySubProjectIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeySubProjectIdx.setRequiredSubProjectId( existing.getRequiredSubProjectId() );

		CFIntMajorVersionBySubProjectIdxKey newKeySubProjectIdx = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		newKeySubProjectIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeySubProjectIdx.setRequiredSubProjectId( Buff.getRequiredSubProjectId() );

		CFIntMajorVersionByNameIdxKey existingKeyNameIdx = schema.getFactoryMajorVersion().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredSubProjectId( existing.getRequiredSubProjectId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntMajorVersionByNameIdxKey newKeyNameIdx = schema.getFactoryMajorVersion().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredSubProjectId( Buff.getRequiredSubProjectId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateMajorVersion",
					"MajorVersionNameIdx",
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
						"updateMajorVersion",
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
				if( null == schema.getTableSubProject().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredSubProjectId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateMajorVersion",
						"Container",
						"ParentSubProject",
						"SubProject",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdict;

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
			subdict = new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySubProjectIdx.get( existingKeySubProjectIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySubProjectIdx.containsKey( newKeySubProjectIdx ) ) {
			subdict = dictBySubProjectIdx.get( newKeySubProjectIdx );
		}
		else {
			subdict = new HashMap< CFIntMajorVersionPKey, CFIntMajorVersionBuff >();
			dictBySubProjectIdx.put( newKeySubProjectIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteMajorVersion( CFSecAuthorization Authorization,
		CFIntMajorVersionBuff Buff )
	{
		final String S_ProcName = "CFIntRamMajorVersionTable.deleteMajorVersion() ";
		String classCode;
		CFIntMajorVersionPKey pkey = schema.getFactoryMajorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntMajorVersionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteMajorVersion",
				pkey );
		}
					schema.getTableMinorVersion().deleteMinorVersionByMajorVerIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
		CFIntMajorVersionByTenantIdxKey keyTenantIdx = schema.getFactoryMajorVersion().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntMajorVersionBySubProjectIdxKey keySubProjectIdx = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		keySubProjectIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keySubProjectIdx.setRequiredSubProjectId( existing.getRequiredSubProjectId() );

		CFIntMajorVersionByNameIdxKey keyNameIdx = schema.getFactoryMajorVersion().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredSubProjectId( existing.getRequiredSubProjectId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntMajorVersionPKey, CFIntMajorVersionBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictBySubProjectIdx.get( keySubProjectIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteMajorVersionByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntMajorVersionPKey key = schema.getFactoryMajorVersion().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteMajorVersionByIdIdx( Authorization, key );
	}

	public void deleteMajorVersionByIdIdx( CFSecAuthorization Authorization,
		CFIntMajorVersionPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntMajorVersionBuff cur;
		LinkedList<CFIntMajorVersionBuff> matchSet = new LinkedList<CFIntMajorVersionBuff>();
		Iterator<CFIntMajorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMajorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMajorVersion( Authorization, cur );
		}
	}

	public void deleteMajorVersionByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntMajorVersionByTenantIdxKey key = schema.getFactoryMajorVersion().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteMajorVersionByTenantIdx( Authorization, key );
	}

	public void deleteMajorVersionByTenantIdx( CFSecAuthorization Authorization,
		CFIntMajorVersionByTenantIdxKey argKey )
	{
		CFIntMajorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMajorVersionBuff> matchSet = new LinkedList<CFIntMajorVersionBuff>();
		Iterator<CFIntMajorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMajorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMajorVersion( Authorization, cur );
		}
	}

	public void deleteMajorVersionBySubProjectIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argSubProjectId )
	{
		CFIntMajorVersionBySubProjectIdxKey key = schema.getFactoryMajorVersion().newSubProjectIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredSubProjectId( argSubProjectId );
		deleteMajorVersionBySubProjectIdx( Authorization, key );
	}

	public void deleteMajorVersionBySubProjectIdx( CFSecAuthorization Authorization,
		CFIntMajorVersionBySubProjectIdxKey argKey )
	{
		CFIntMajorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMajorVersionBuff> matchSet = new LinkedList<CFIntMajorVersionBuff>();
		Iterator<CFIntMajorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMajorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMajorVersion( Authorization, cur );
		}
	}

	public void deleteMajorVersionByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argSubProjectId,
		String argName )
	{
		CFIntMajorVersionByNameIdxKey key = schema.getFactoryMajorVersion().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredSubProjectId( argSubProjectId );
		key.setRequiredName( argName );
		deleteMajorVersionByNameIdx( Authorization, key );
	}

	public void deleteMajorVersionByNameIdx( CFSecAuthorization Authorization,
		CFIntMajorVersionByNameIdxKey argKey )
	{
		CFIntMajorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMajorVersionBuff> matchSet = new LinkedList<CFIntMajorVersionBuff>();
		Iterator<CFIntMajorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMajorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMajorVersion( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
