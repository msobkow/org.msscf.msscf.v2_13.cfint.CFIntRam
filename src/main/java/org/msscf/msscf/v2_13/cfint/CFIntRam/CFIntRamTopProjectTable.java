
// Description: Java 11 in-memory RAM DbIO implementation for TopProject.

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
 *	CFIntRamTopProjectTable in-memory RAM DbIO implementation
 *	for TopProject.
 */
public class CFIntRamTopProjectTable
	implements ICFIntTopProjectTable
{
	private ICFIntSchema schema;
	private Map< CFIntTopProjectPKey,
				CFIntTopProjectBuff > dictByPKey
		= new HashMap< CFIntTopProjectPKey,
				CFIntTopProjectBuff >();
	private Map< CFIntTopProjectByTenantIdxKey,
				Map< CFIntTopProjectPKey,
					CFIntTopProjectBuff >> dictByTenantIdx
		= new HashMap< CFIntTopProjectByTenantIdxKey,
				Map< CFIntTopProjectPKey,
					CFIntTopProjectBuff >>();
	private Map< CFIntTopProjectByTopDomainIdxKey,
				Map< CFIntTopProjectPKey,
					CFIntTopProjectBuff >> dictByTopDomainIdx
		= new HashMap< CFIntTopProjectByTopDomainIdxKey,
				Map< CFIntTopProjectPKey,
					CFIntTopProjectBuff >>();
	private Map< CFIntTopProjectByNameIdxKey,
			CFIntTopProjectBuff > dictByNameIdx
		= new HashMap< CFIntTopProjectByNameIdxKey,
			CFIntTopProjectBuff >();

	public CFIntRamTopProjectTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createTopProject( CFSecAuthorization Authorization,
		CFIntTopProjectBuff Buff )
	{
		final String S_ProcName = "createTopProject";
		CFIntTopProjectPKey pkey = schema.getFactoryTopProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( ((CFIntRamTenantTable)schema.getTableTenant()).nextTopProjectIdGen( Authorization,
			Buff.getRequiredTenantId() ) );
		Buff.setRequiredTenantId( pkey.getRequiredTenantId() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFIntTopProjectByTenantIdxKey keyTenantIdx = schema.getFactoryTopProject().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTopProjectByTopDomainIdxKey keyTopDomainIdx = schema.getFactoryTopProject().newTopDomainIdxKey();
		keyTopDomainIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyTopDomainIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );

		CFIntTopProjectByNameIdxKey keyNameIdx = schema.getFactoryTopProject().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyNameIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TopProjectNameIdx",
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
				if( null == schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopDomainId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"ParentTopDomain",
						"TopDomain",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTopDomainIdx;
		if( dictByTopDomainIdx.containsKey( keyTopDomainIdx ) ) {
			subdictTopDomainIdx = dictByTopDomainIdx.get( keyTopDomainIdx );
		}
		else {
			subdictTopDomainIdx = new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTopDomainIdx.put( keyTopDomainIdx, subdictTopDomainIdx );
		}
		subdictTopDomainIdx.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

	}

	public CFIntTopProjectBuff readDerived( CFSecAuthorization Authorization,
		CFIntTopProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerived";
		CFIntTopProjectPKey key = schema.getFactoryTopProject().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTopProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff lockDerived( CFSecAuthorization Authorization,
		CFIntTopProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerived";
		CFIntTopProjectPKey key = schema.getFactoryTopProject().newPKey();
		key.setRequiredTenantId( PKey.getRequiredTenantId() );
		key.setRequiredId( PKey.getRequiredId() );
		CFIntTopProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamTopProject.readAllDerived";
		CFIntTopProjectBuff[] retList = new CFIntTopProjectBuff[ dictByPKey.values().size() ];
		Iterator< CFIntTopProjectBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFIntTopProjectBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerivedByTenantIdx";
		CFIntTopProjectByTenantIdxKey key = schema.getFactoryTopProject().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFIntTopProjectBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFIntTopProjectBuff[ subdictTenantIdx.size() ];
			Iterator< CFIntTopProjectBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTenantIdx
				= new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFIntTopProjectBuff[0];
		}
		return( recArray );
	}

	public CFIntTopProjectBuff[] readDerivedByTopDomainIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerivedByTopDomainIdx";
		CFIntTopProjectByTopDomainIdxKey key = schema.getFactoryTopProject().newTopDomainIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopDomainId( TopDomainId );

		CFIntTopProjectBuff[] recArray;
		if( dictByTopDomainIdx.containsKey( key ) ) {
			Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTopDomainIdx
				= dictByTopDomainIdx.get( key );
			recArray = new CFIntTopProjectBuff[ subdictTopDomainIdx.size() ];
			Iterator< CFIntTopProjectBuff > iter = subdictTopDomainIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdictTopDomainIdx
				= new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTopDomainIdx.put( key, subdictTopDomainIdx );
			recArray = new CFIntTopProjectBuff[0];
		}
		return( recArray );
	}

	public CFIntTopProjectBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerivedByNameIdx";
		CFIntTopProjectByNameIdxKey key = schema.getFactoryTopProject().newNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTopDomainId( TopDomainId );
		key.setRequiredName( Name );

		CFIntTopProjectBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTopProject.readDerivedByIdIdx() ";
		CFIntTopProjectPKey key = schema.getFactoryTopProject().newPKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredId( Id );

		CFIntTopProjectBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff readBuff( CFSecAuthorization Authorization,
		CFIntTopProjectPKey PKey )
	{
		final String S_ProcName = "CFIntRamTopProject.readBuff";
		CFIntTopProjectBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a108" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff lockBuff( CFSecAuthorization Authorization,
		CFIntTopProjectPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFIntTopProjectBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a108" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFIntTopProjectBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamTopProject.readAllBuff";
		CFIntTopProjectBuff buff;
		ArrayList<CFIntTopProjectBuff> filteredList = new ArrayList<CFIntTopProjectBuff>();
		CFIntTopProjectBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a108" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFIntTopProjectBuff[0] ) );
	}

	public CFIntTopProjectBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long TenantId,
		long Id )
	{
		final String S_ProcName = "CFIntRamTopProject.readBuffByIdIdx() ";
		CFIntTopProjectBuff buff = readDerivedByIdIdx( Authorization,
			TenantId,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a108" ) ) {
			return( (CFIntTopProjectBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFIntTopProjectBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		long TenantId )
	{
		final String S_ProcName = "CFIntRamTopProject.readBuffByTenantIdx() ";
		CFIntTopProjectBuff buff;
		ArrayList<CFIntTopProjectBuff> filteredList = new ArrayList<CFIntTopProjectBuff>();
		CFIntTopProjectBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a108" ) ) {
				filteredList.add( (CFIntTopProjectBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntTopProjectBuff[0] ) );
	}

	public CFIntTopProjectBuff[] readBuffByTopDomainIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId )
	{
		final String S_ProcName = "CFIntRamTopProject.readBuffByTopDomainIdx() ";
		CFIntTopProjectBuff buff;
		ArrayList<CFIntTopProjectBuff> filteredList = new ArrayList<CFIntTopProjectBuff>();
		CFIntTopProjectBuff[] buffList = readDerivedByTopDomainIdx( Authorization,
			TenantId,
			TopDomainId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a108" ) ) {
				filteredList.add( (CFIntTopProjectBuff)buff );
			}
		}
		return( filteredList.toArray( new CFIntTopProjectBuff[0] ) );
	}

	public CFIntTopProjectBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		long TenantId,
		long TopDomainId,
		String Name )
	{
		final String S_ProcName = "CFIntRamTopProject.readBuffByNameIdx() ";
		CFIntTopProjectBuff buff = readDerivedByNameIdx( Authorization,
			TenantId,
			TopDomainId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a108" ) ) {
			return( (CFIntTopProjectBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateTopProject( CFSecAuthorization Authorization,
		CFIntTopProjectBuff Buff )
	{
		CFIntTopProjectPKey pkey = schema.getFactoryTopProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTopProjectBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTopProject",
				"Existing record not found",
				"TopProject",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTopProject",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFIntTopProjectByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTopProject().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTopProjectByTenantIdxKey newKeyTenantIdx = schema.getFactoryTopProject().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFIntTopProjectByTopDomainIdxKey existingKeyTopDomainIdx = schema.getFactoryTopProject().newTopDomainIdxKey();
		existingKeyTopDomainIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyTopDomainIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );

		CFIntTopProjectByTopDomainIdxKey newKeyTopDomainIdx = schema.getFactoryTopProject().newTopDomainIdxKey();
		newKeyTopDomainIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyTopDomainIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );

		CFIntTopProjectByNameIdxKey existingKeyNameIdx = schema.getFactoryTopProject().newNameIdxKey();
		existingKeyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyNameIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFIntTopProjectByNameIdxKey newKeyNameIdx = schema.getFactoryTopProject().newNameIdxKey();
		newKeyNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyNameIdx.setRequiredTopDomainId( Buff.getRequiredTopDomainId() );
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTopProject",
					"TopProjectNameIdx",
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
						"updateTopProject",
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
				if( null == schema.getTableTopDomain().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId(),
						Buff.getRequiredTopDomainId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTopProject",
						"Container",
						"ParentTopDomain",
						"TopDomain",
						null );
				}
			}
		}

		// Update is valid

		Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdict;

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
			subdict = new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTopDomainIdx.get( existingKeyTopDomainIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTopDomainIdx.containsKey( newKeyTopDomainIdx ) ) {
			subdict = dictByTopDomainIdx.get( newKeyTopDomainIdx );
		}
		else {
			subdict = new HashMap< CFIntTopProjectPKey, CFIntTopProjectBuff >();
			dictByTopDomainIdx.put( newKeyTopDomainIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

	}

	public void deleteTopProject( CFSecAuthorization Authorization,
		CFIntTopProjectBuff Buff )
	{
		final String S_ProcName = "CFIntRamTopProjectTable.deleteTopProject() ";
		String classCode;
		CFIntTopProjectPKey pkey = schema.getFactoryTopProject().newPKey();
		pkey.setRequiredTenantId( Buff.getRequiredTenantId() );
		pkey.setRequiredId( Buff.getRequiredId() );
		CFIntTopProjectBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTopProject",
				pkey );
		}
					schema.getTableSubProject().deleteSubProjectByTopProjectIdx( Authorization,
						existing.getRequiredTenantId(),
						existing.getRequiredId() );
		CFIntTopProjectByTenantIdxKey keyTenantIdx = schema.getFactoryTopProject().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFIntTopProjectByTopDomainIdxKey keyTopDomainIdx = schema.getFactoryTopProject().newTopDomainIdxKey();
		keyTopDomainIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyTopDomainIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );

		CFIntTopProjectByNameIdxKey keyNameIdx = schema.getFactoryTopProject().newNameIdxKey();
		keyNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyNameIdx.setRequiredTopDomainId( existing.getRequiredTopDomainId() );
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFIntTopProjectPKey, CFIntTopProjectBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByTopDomainIdx.get( keyTopDomainIdx );
		subdict.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteTopProjectByIdIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argId )
	{
		CFIntTopProjectPKey key = schema.getFactoryTopProject().newPKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredId( argId );
		deleteTopProjectByIdIdx( Authorization, key );
	}

	public void deleteTopProjectByIdIdx( CFSecAuthorization Authorization,
		CFIntTopProjectPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFIntTopProjectBuff cur;
		LinkedList<CFIntTopProjectBuff> matchSet = new LinkedList<CFIntTopProjectBuff>();
		Iterator<CFIntTopProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopProject( Authorization, cur );
		}
	}

	public void deleteTopProjectByTenantIdx( CFSecAuthorization Authorization,
		long argTenantId )
	{
		CFIntTopProjectByTenantIdxKey key = schema.getFactoryTopProject().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTopProjectByTenantIdx( Authorization, key );
	}

	public void deleteTopProjectByTenantIdx( CFSecAuthorization Authorization,
		CFIntTopProjectByTenantIdxKey argKey )
	{
		CFIntTopProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopProjectBuff> matchSet = new LinkedList<CFIntTopProjectBuff>();
		Iterator<CFIntTopProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopProject( Authorization, cur );
		}
	}

	public void deleteTopProjectByTopDomainIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopDomainId )
	{
		CFIntTopProjectByTopDomainIdxKey key = schema.getFactoryTopProject().newTopDomainIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopDomainId( argTopDomainId );
		deleteTopProjectByTopDomainIdx( Authorization, key );
	}

	public void deleteTopProjectByTopDomainIdx( CFSecAuthorization Authorization,
		CFIntTopProjectByTopDomainIdxKey argKey )
	{
		CFIntTopProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopProjectBuff> matchSet = new LinkedList<CFIntTopProjectBuff>();
		Iterator<CFIntTopProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopProject( Authorization, cur );
		}
	}

	public void deleteTopProjectByNameIdx( CFSecAuthorization Authorization,
		long argTenantId,
		long argTopDomainId,
		String argName )
	{
		CFIntTopProjectByNameIdxKey key = schema.getFactoryTopProject().newNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTopDomainId( argTopDomainId );
		key.setRequiredName( argName );
		deleteTopProjectByNameIdx( Authorization, key );
	}

	public void deleteTopProjectByNameIdx( CFSecAuthorization Authorization,
		CFIntTopProjectByNameIdxKey argKey )
	{
		CFIntTopProjectBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFIntTopProjectBuff> matchSet = new LinkedList<CFIntTopProjectBuff>();
		Iterator<CFIntTopProjectBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFIntTopProjectBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTopProject().readDerivedByIdIdx( Authorization,
				cur.getRequiredTenantId(),
				cur.getRequiredId() );
			deleteTopProject( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
