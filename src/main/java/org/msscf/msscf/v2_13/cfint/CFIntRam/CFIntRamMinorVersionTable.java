
// Description: Java 11 in-memory RAM DbIO implementation for MinorVersion.

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
 *	CFIntRamMinorVersionTable in-memory RAM DbIO implementation
 *	for MinorVersion.
 */
public class CFIntRamMinorVersionTable
	implements ICFIntMinorVersionTable
{
	private ICFIntSchema schema;
	private Map< CFIntMinorVersionPKey,
				CFIntMinorVersionBuff > dictByPKey
		= new HashMap< CFIntMinorVersionPKey,
				CFIntMinorVersionBuff >();
	private Map< CFIntMinorVersionByTenantIdxKey,
				Map< CFIntMinorVersionPKey,
					CFIntMinorVersionBuff >> dictByTenantIdx
		= new HashMap< CFIntMinorVersionByTenantIdxKey,
				Map< CFIntMinorVersionPKey,
					CFIntMinorVersionBuff >>();
	private Map< CFIntMinorVersionByMajorVerIdxKey,
				Map< CFIntMinorVersionPKey,
					CFIntMinorVersionBuff >> dictByMajorVerIdx
		= new HashMap< CFIntMinorVersionByMajorVerIdxKey,
				Map< CFIntMinorVersionPKey,
					CFIntMinorVersionBuff >>();
	private Map< CFIntMinorVersionByNameIdxKey,
			CFIntMinorVersionBuff > dictByNameIdx
		= new HashMap< CFIntMinorVersionByNameIdxKey,
			CFIntMinorVersionBuff >();

	public CFIntRamMinorVersionTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createMinorVersion( CFSecAuthorization Authorization,
		CFIntMinorVersionBuff Buff )
	{
		final String S_ProcName = "createMinorVersion";
		CFIntMinorVersionPKey pkey = schema.getFactoryMinorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextMinorVersionIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntMinorVersionByTenantIdxKey keyTenantIdx = schema.getFactoryMinorVersion().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntMinorVersionByMajorVerIdxKey keyMajorVerIdx = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		keyMajorVerIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyMajorVerIdx.setRequiredMajorVersionId( Buff.getRequiredMajorVersionId() );

		CFIntMinorVersionByNameIdxKey keyNameIdx = schema.getFactoryMinorVersion().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredMajorVersionId( Buff.getRequiredMajorVersionId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"MinorVersionNameIdx",
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
				if( null == schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredMajorVersionId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ParentMajorVersion",
						"MajorVersion",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictMajorVerIdx;
		if( dictByMajorVerIdx.containsKey( keyMajorVerIdx ) ) {
			subdictMajorVerIdx = dictByMajorVerIdx.get( keyMajorVerIdx );
		}
		else {
			subdictMajorVerIdx = new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByMajorVerIdx.put( keyMajorVerIdx, subdictMajorVerIdx );
		}
		subdictMajorVerIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntMinorVersionBuff readDerived( CFSecAuthorization Authorization,
		CFIntMinorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerived";
		CFIntMinorVersionPKey key = schema.getFactoryMinorVersion().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntMinorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff lockDerived( CFSecAuthorization Authorization,
		CFIntMinorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerived";
		CFIntMinorVersionPKey key = schema.getFactoryMinorVersion().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntMinorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamMinorVersion.readAllDerived";
		CFIntMinorVersionBuff[] retList = new CFIntMinorVersionBuff[ dictByPKey.values().size() ];
		Iterator< CFIntMinorVersionBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntMinorVersionBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerivedByTenantIdx";
		CFIntMinorVersionByTenantIdxKey key = schema.getFactoryMinorVersion().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntMinorVersionBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntMinorVersionBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntMinorVersionBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictTenantIdx
				= new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntMinorVersionBuff[0];
		}
		return( recArray );
	}

	public CFIntMinorVersionBuff[] readDerivedByMajorVerIdx( CFSecAuthorization Authorization,
		long TenantId,
		long MajorVersionId )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerivedByMajorVerIdx";
		CFIntMinorVersionByMajorVerIdxKey key = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredMajorVersionId( MajorVersionId );

		CFIntMinorVersionBuff[] recArray;
		if( dictByMajorVerIdx.containsKey( key ) ) {
			Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictMajorVerIdx
				= dictByMajorVerIdx.get( key );
			recArray = new CFIntMinorVersionBuff[ subdictMajorVerIdx.size() ];
			Iterator< CFIntMinorVersionBuff > iter = subdictMajorVerIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdictMajorVerIdx
				= new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByMajorVerIdx.put( key, subdictMajorVerIdx );
			recArray = new CFIntMinorVersionBuff[0];
		}
		return( recArray );
	}

	public CFIntMinorVersionBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long MajorVersionId,
		String Name )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerivedByNameIdx";
		CFIntMinorVersionByNameIdxKey key = schema.getFactoryMinorVersion().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredMajorVersionId( MajorVersionId );
		key.setRequiredName( Name );

		CFIntMinorVersionBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readDerivedByIdIdx() ";
		CFIntMinorVersionPKey key = schema.getFactoryMinorVersion().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntMinorVersionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff readBuff( CFSecAuthorization Authorization,
		CFIntMinorVersionPKey PKey )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readBuff";
		CFIntMinorVersionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a104" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff lockBuff( CFSecAuthorization Authorization,
		CFIntMinorVersionPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntMinorVersionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a104" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntMinorVersionBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readAllBuff";
		CFIntMinorVersionBuff buff;
		ArrayList<CFIntMinorVersionBuff> filteredList = new ArrayList<CFIntMinorVersionBuff>();
		CFIntMinorVersionBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a104" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntMinorVersionBuff[0] ) );
	}

	public CFIntMinorVersionBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readBuffByIdIdx() ";
		CFIntMinorVersionBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a104" ) ) {
			return( (CFIntMinorVersionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntMinorVersionBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readBuffByTenantIdx() ";
		CFIntMinorVersionBuff buff;
		ArrayList<CFIntMinorVersionBuff> filteredList = new ArrayList<CFIntMinorVersionBuff>();
		CFIntMinorVersionBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a104" ) ) {
				filteredList.add( (CFIntMinorVersionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntMinorVersionBuff[0] ) );
	}

	public CFIntMinorVersionBuff[] readBuffByMajorVerIdx( CFSecAuthorization Authorization,
		long TenantId,
		long MajorVersionId )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readBuffByMajorVerIdx() ";
		CFIntMinorVersionBuff buff;
		ArrayList<CFIntMinorVersionBuff> filteredList = new ArrayList<CFIntMinorVersionBuff>();
		CFIntMinorVersionBuff[] buffList = readDerivedByMajorVerIdx( Authorization,
			TenantId,
			MajorVersionId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a104" ) ) {
				filteredList.add( (CFIntMinorVersionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntMinorVersionBuff[0] ) );
	}

	public CFIntMinorVersionBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long MajorVersionId,
		String Name )
	{
		final String S_ProcName = "CFIntRamMinorVersion.readBuffByNameIdx() ";
		CFIntMinorVersionBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			MajorVersionId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a104" ) ) {
			return( (CFIntMinorVersionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateMinorVersion( CFSecAuthorization Authorization,
		CFIntMinorVersionBuff Buff )
	{
		CFIntMinorVersionPKey pkey = schema.getFactoryMinorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntMinorVersionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateMinorVersion",
				"Existing record not found",
				"MinorVersion",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateMinorVersion",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntMinorVersionByTenantIdxKey existingKeyTenantIdx = schema.getFactoryMinorVersion().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntMinorVersionByTenantIdxKey newKeyTenantIdx = schema.getFactoryMinorVersion().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntMinorVersionByMajorVerIdxKey existingKeyMajorVerIdx = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		existingKeyMajorVerIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyMajorVerIdx.setRequiredMajorVersionId( existing.getRequiredMajorVersionId() );

		CFIntMinorVersionByMajorVerIdxKey newKeyMajorVerIdx = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		newKeyMajorVerIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyMajorVerIdx.setRequiredMajorVersionId( Buff.getRequiredMajorVersionId() );

		CFIntMinorVersionByNameIdxKey existingKeyNameIdx = schema.getFactoryMinorVersion().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredMajorVersionId( existing.getRequiredMajorVersionId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntMinorVersionByNameIdxKey newKeyNameIdx = schema.getFactoryMinorVersion().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredMajorVersionId( Buff.getRequiredMajorVersionId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateMinorVersion",
					"MinorVersionNameIdx",
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
						"updateMinorVersion",
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
				if( null == schema.getTableMajorVersion().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredMajorVersionId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateMinorVersion",
						"Container",
						"ParentMajorVersion",
						"MajorVersion",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdict;

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
			subdict = new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByMajorVerIdx.get( existingKeyMajorVerIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByMajorVerIdx.containsKey( newKeyMajorVerIdx ) ) {
			subdict = dictByMajorVerIdx.get( newKeyMajorVerIdx );
		}
		else {
			subdict = new HashMap< CFIntMinorVersionPKey, CFIntMinorVersionBuff >();
			dictByMajorVerIdx.put( newKeyMajorVerIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteMinorVersion( CFSecAuthorization Authorization,
		CFIntMinorVersionBuff Buff )
	{
		final String S_ProcName = "CFIntRamMinorVersionTable.deleteMinorVersion() ";
		String classCode;
		CFIntMinorVersionPKey pkey = schema.getFactoryMinorVersion().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntMinorVersionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteMinorVersion",
				pkey );
		}
		CFIntMinorVersionByTenantIdxKey keyTenantIdx = schema.getFactoryMinorVersion().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntMinorVersionByMajorVerIdxKey keyMajorVerIdx = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		keyMajorVerIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyMajorVerIdx.setRequiredMajorVersionId( existing.getRequiredMajorVersionId() );

		CFIntMinorVersionByNameIdxKey keyNameIdx = schema.getFactoryMinorVersion().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredMajorVersionId( existing.getRequiredMajorVersionId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntMinorVersionPKey, CFIntMinorVersionBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByMajorVerIdx.get( keyMajorVerIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteMinorVersionByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntMinorVersionPKey key = schema.getFactoryMinorVersion().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteMinorVersionByIdIdx( Authorization, key );
	}

	public void deleteMinorVersionByIdIdx( CFSecAuthorization Authorization,
		CFIntMinorVersionPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntMinorVersionBuff cur;
		LinkedList<CFIntMinorVersionBuff> matchSet = new LinkedList<CFIntMinorVersionBuff>();
		Iterator<CFIntMinorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMinorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMinorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMinorVersion( Authorization, cur );
		}
	}

	public void deleteMinorVersionByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntMinorVersionByTenantIdxKey key = schema.getFactoryMinorVersion().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteMinorVersionByTenantIdx( Authorization, key );
	}

	public void deleteMinorVersionByTenantIdx( CFSecAuthorization Authorization,
		CFIntMinorVersionByTenantIdxKey argKey )
	{
		CFIntMinorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMinorVersionBuff> matchSet = new LinkedList<CFIntMinorVersionBuff>();
		Iterator<CFIntMinorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMinorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMinorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMinorVersion( Authorization, cur );
		}
	}

	public void deleteMinorVersionByMajorVerIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argMajorVersionId )
	{
		CFIntMinorVersionByMajorVerIdxKey key = schema.getFactoryMinorVersion().newMajorVerIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredMajorVersionId( argMajorVersionId );
		deleteMinorVersionByMajorVerIdx( Authorization, key );
	}

	public void deleteMinorVersionByMajorVerIdx( CFSecAuthorization Authorization,
		CFIntMinorVersionByMajorVerIdxKey argKey )
	{
		CFIntMinorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMinorVersionBuff> matchSet = new LinkedList<CFIntMinorVersionBuff>();
		Iterator<CFIntMinorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMinorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMinorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMinorVersion( Authorization, cur );
		}
	}

	public void deleteMinorVersionByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argMajorVersionId,
		String argName )
	{
		CFIntMinorVersionByNameIdxKey key = schema.getFactoryMinorVersion().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredMajorVersionId( argMajorVersionId );
		key.setRequiredName( argName );
		deleteMinorVersionByNameIdx( Authorization, key );
	}

	public void deleteMinorVersionByNameIdx( CFSecAuthorization Authorization,
		CFIntMinorVersionByNameIdxKey argKey )
	{
		CFIntMinorVersionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntMinorVersionBuff> matchSet = new LinkedList<CFIntMinorVersionBuff>();
		Iterator<CFIntMinorVersionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntMinorVersionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableMinorVersion().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteMinorVersion( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
