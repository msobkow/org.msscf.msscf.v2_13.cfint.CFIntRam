
// Description: Java 11 in-memory RAM DbIO implementation for SubProject.

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
 *	CFIntRamSubProjectTable in-memory RAM DbIO implementation
 *	for SubProject.
 */
public class CFIntRamSubProjectTable
	implements ICFIntSubProjectTable
{
	private ICFIntSchema schema;
	private Map< CFIntSubProjectPKey,
				CFIntSubProjectBuff > dictByPKey
		= new HashMap< CFIntSubProjectPKey,
				CFIntSubProjectBuff >();
	private Map< CFIntSubProjectByTenantIdxKey,
				Map< CFIntSubProjectPKey,
					CFIntSubProjectBuff >> dictByTenantIdx
		= new HashMap< CFIntSubProjectByTenantIdxKey,
				Map< CFIntSubProjectPKey,
					CFIntSubProjectBuff >>();
	private Map< CFIntSubProjectByTopProjectIdxKey,
				Map< CFIntSubProjectPKey,
					CFIntSubProjectBuff >> dictByTopProjectIdx
		= new HashMap< CFIntSubProjectByTopProjectIdxKey,
				Map< CFIntSubProjectPKey,
					CFIntSubProjectBuff >>();
	private Map< CFIntSubProjectByNameIdxKey,
			CFIntSubProjectBuff > dictByNameIdx
		= new HashMap< CFIntSubProjectByNameIdxKey,
			CFIntSubProjectBuff >();

	public CFIntRamSubProjectTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSubProject( CFSecAuthorization Authorization,
		CFIntSubProjectBuff Buff )
	{
		final String S_ProcName = "createSubProject";
		CFIntSubProjectPKey pkey = schema.getFactorySubProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextSubProjectIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntSubProjectByTenantIdxKey keyTenantIdx = schema.getFactorySubProject().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntSubProjectByTopProjectIdxKey keyTopProjectIdx = schema.getFactorySubProject().newTopProjectIdxKey();
		keyTopProjectIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyTopProjectIdx.setRequiredTopProjectId( Buff.getRequiredTopProjectId() );

		CFIntSubProjectByNameIdxKey keyNameIdx = schema.getFactorySubProject().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredTopProjectId( Buff.getRequiredTopProjectId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SubProjectNameIdx",
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
				if( null == schema.getTableTopProject().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopProjectId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ParentTopProject",
						"TopProject",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTopProjectIdx;
		if( dictByTopProjectIdx.containsKey( keyTopProjectIdx ) ) {
			subdictTopProjectIdx = dictByTopProjectIdx.get( keyTopProjectIdx );
		}
		else {
			subdictTopProjectIdx = new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTopProjectIdx.put( keyTopProjectIdx, subdictTopProjectIdx );
		}
		subdictTopProjectIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntSubProjectBuff readDerived( CFSecAuthorization Authorization,
		CFIntSubProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerived";
		CFIntSubProjectPKey key = schema.getFactorySubProject().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntSubProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff lockDerived( CFSecAuthorization Authorization,
		CFIntSubProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerived";
		CFIntSubProjectPKey key = schema.getFactorySubProject().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntSubProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSubProject.readAllDerived";
		CFIntSubProjectBuff[] retList = new CFIntSubProjectBuff[ dictByPKey.values().size() ];
		Iterator< CFIntSubProjectBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntSubProjectBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerivedByTenantIdx";
		CFIntSubProjectByTenantIdxKey key = schema.getFactorySubProject().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntSubProjectBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntSubProjectBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntSubProjectBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTenantIdx
				= new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntSubProjectBuff[0];
		}
		return( recArray );
	}

	public CFIntSubProjectBuff[] readDerivedByTopProjectIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopProjectId )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerivedByTopProjectIdx";
		CFIntSubProjectByTopProjectIdxKey key = schema.getFactorySubProject().newTopProjectIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopProjectId( TopProjectId );

		CFIntSubProjectBuff[] recArray;
		if( dictByTopProjectIdx.containsKey( key ) ) {
			Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTopProjectIdx
				= dictByTopProjectIdx.get( key );
			recArray = new CFIntSubProjectBuff[ subdictTopProjectIdx.size() ];
			Iterator< CFIntSubProjectBuff > iter = subdictTopProjectIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdictTopProjectIdx
				= new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTopProjectIdx.put( key, subdictTopProjectIdx );
			recArray = new CFIntSubProjectBuff[0];
		}
		return( recArray );
	}

	public CFIntSubProjectBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopProjectId,
		String Name )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerivedByNameIdx";
		CFIntSubProjectByNameIdxKey key = schema.getFactorySubProject().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopProjectId( TopProjectId );
		key.setRequiredName( Name );

		CFIntSubProjectBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamSubProject.readDerivedByIdIdx() ";
		CFIntSubProjectPKey key = schema.getFactorySubProject().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntSubProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff readBuff( CFSecAuthorization Authorization,
		CFIntSubProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamSubProject.readBuff";
		CFIntSubProjectBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a105" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff lockBuff( CFSecAuthorization Authorization,
		CFIntSubProjectPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntSubProjectBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a105" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntSubProjectBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSubProject.readAllBuff";
		CFIntSubProjectBuff buff;
		ArrayList<CFIntSubProjectBuff> filteredList = new ArrayList<CFIntSubProjectBuff>();
		CFIntSubProjectBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a105" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntSubProjectBuff[0] ) );
	}

	public CFIntSubProjectBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamSubProject.readBuffByIdIdx() ";
		CFIntSubProjectBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a105" ) ) {
			return( (CFIntSubProjectBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntSubProjectBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamSubProject.readBuffByTenantIdx() ";
		CFIntSubProjectBuff buff;
		ArrayList<CFIntSubProjectBuff> filteredList = new ArrayList<CFIntSubProjectBuff>();
		CFIntSubProjectBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a105" ) ) {
				filteredList.add( (CFIntSubProjectBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntSubProjectBuff[0] ) );
	}

	public CFIntSubProjectBuff[] readBuffByTopProjectIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopProjectId )
	{
		final String S_ProcName = "CFIntRamSubProject.readBuffByTopProjectIdx() ";
		CFIntSubProjectBuff buff;
		ArrayList<CFIntSubProjectBuff> filteredList = new ArrayList<CFIntSubProjectBuff>();
		CFIntSubProjectBuff[] buffList = readDerivedByTopProjectIdx( Authorization,
			TenantId,
			TopProjectId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a105" ) ) {
				filteredList.add( (CFIntSubProjectBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntSubProjectBuff[0] ) );
	}

	public CFIntSubProjectBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopProjectId,
		String Name )
	{
		final String S_ProcName = "CFIntRamSubProject.readBuffByNameIdx() ";
		CFIntSubProjectBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			TopProjectId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a105" ) ) {
			return( (CFIntSubProjectBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateSubProject( CFSecAuthorization Authorization,
		CFIntSubProjectBuff Buff )
	{
		CFIntSubProjectPKey pkey = schema.getFactorySubProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntSubProjectBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSubProject",
				"Existing record not found",
				"SubProject",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSubProject",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntSubProjectByTenantIdxKey existingKeyTenantIdx = schema.getFactorySubProject().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntSubProjectByTenantIdxKey newKeyTenantIdx = schema.getFactorySubProject().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntSubProjectByTopProjectIdxKey existingKeyTopProjectIdx = schema.getFactorySubProject().newTopProjectIdxKey();
		existingKeyTopProjectIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyTopProjectIdx.setRequiredTopProjectId( existing.getRequiredTopProjectId() );

		CFIntSubProjectByTopProjectIdxKey newKeyTopProjectIdx = schema.getFactorySubProject().newTopProjectIdxKey();
		newKeyTopProjectIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyTopProjectIdx.setRequiredTopProjectId( Buff.getRequiredTopProjectId() );

		CFIntSubProjectByNameIdxKey existingKeyNameIdx = schema.getFactorySubProject().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredTopProjectId( existing.getRequiredTopProjectId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntSubProjectByNameIdxKey newKeyNameIdx = schema.getFactorySubProject().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredTopProjectId( Buff.getRequiredTopProjectId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSubProject",
					"SubProjectNameIdx",
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
						"updateSubProject",
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
				if( null == schema.getTableTopProject().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopProjectId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSubProject",
						"Container",
						"ParentTopProject",
						"TopProject",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdict;

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
			subdict = new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTopProjectIdx.get( existingKeyTopProjectIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTopProjectIdx.containsKey( newKeyTopProjectIdx ) ) {
			subdict = dictByTopProjectIdx.get( newKeyTopProjectIdx );
		}
		else {
			subdict = new HashMap< CFIntSubProjectPKey, CFIntSubProjectBuff >();
			dictByTopProjectIdx.put( newKeyTopProjectIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteSubProject( CFSecAuthorization Authorization,
		CFIntSubProjectBuff Buff )
	{
		final String S_ProcName = "CFIntRamSubProjectTable.deleteSubProject() ";
		String classCode;
		CFIntSubProjectPKey pkey = schema.getFactorySubProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntSubProjectBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSubProject",
				pkey );
		}
					schema.getTableMajorVersion().deleteMajorVersionBySubProjectIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
		CFIntSubProjectByTenantIdxKey keyTenantIdx = schema.getFactorySubProject().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntSubProjectByTopProjectIdxKey keyTopProjectIdx = schema.getFactorySubProject().newTopProjectIdxKey();
		keyTopProjectIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyTopProjectIdx.setRequiredTopProjectId( existing.getRequiredTopProjectId() );

		CFIntSubProjectByNameIdxKey keyNameIdx = schema.getFactorySubProject().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredTopProjectId( existing.getRequiredTopProjectId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntSubProjectPKey, CFIntSubProjectBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByTopProjectIdx.get( keyTopProjectIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteSubProjectByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntSubProjectPKey key = schema.getFactorySubProject().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteSubProjectByIdIdx( Authorization, key );
	}

	public void deleteSubProjectByIdIdx( CFSecAuthorization Authorization,
		CFIntSubProjectPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntSubProjectBuff cur;
		LinkedList<CFIntSubProjectBuff> matchSet = new LinkedList<CFIntSubProjectBuff>();
		Iterator<CFIntSubProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntSubProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSubProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteSubProject( Authorization, cur );
		}
	}

	public void deleteSubProjectByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntSubProjectByTenantIdxKey key = schema.getFactorySubProject().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteSubProjectByTenantIdx( Authorization, key );
	}

	public void deleteSubProjectByTenantIdx( CFSecAuthorization Authorization,
		CFIntSubProjectByTenantIdxKey argKey )
	{
		CFIntSubProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntSubProjectBuff> matchSet = new LinkedList<CFIntSubProjectBuff>();
		Iterator<CFIntSubProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntSubProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSubProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteSubProject( Authorization, cur );
		}
	}

	public void deleteSubProjectByTopProjectIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopProjectId )
	{
		CFIntSubProjectByTopProjectIdxKey key = schema.getFactorySubProject().newTopProjectIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopProjectId( argTopProjectId );
		deleteSubProjectByTopProjectIdx( Authorization, key );
	}

	public void deleteSubProjectByTopProjectIdx( CFSecAuthorization Authorization,
		CFIntSubProjectByTopProjectIdxKey argKey )
	{
		CFIntSubProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntSubProjectBuff> matchSet = new LinkedList<CFIntSubProjectBuff>();
		Iterator<CFIntSubProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntSubProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSubProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteSubProject( Authorization, cur );
		}
	}

	public void deleteSubProjectByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopProjectId,
		String argName )
	{
		CFIntSubProjectByNameIdxKey key = schema.getFactorySubProject().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopProjectId( argTopProjectId );
		key.setRequiredName( argName );
		deleteSubProjectByNameIdx( Authorization, key );
	}

	public void deleteSubProjectByNameIdx( CFSecAuthorization Authorization,
		CFIntSubProjectByNameIdxKey argKey )
	{
		CFIntSubProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntSubProjectBuff> matchSet = new LinkedList<CFIntSubProjectBuff>();
		Iterator<CFIntSubProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntSubProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSubProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteSubProject( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
