
// Description: Java 11 in-memory RAM DbIO implementation for SecForm.

/*
 *	org.msscf.msscf.CFInt
 *
 *	Copyright (c) 2020 Mark Stephen Sobkow
 *	
 *	MSS Code Factory CFSec 2.13 Security Essentials
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
 *	CFIntRamSecFormTable in-memory RAM DbIO implementation
 *	for SecForm.
 */
public class CFIntRamSecFormTable
	implements ICFIntSecFormTable
{
	private ICFIntSchema schema;
	private Map< CFSecSecFormPKey,
				CFSecSecFormBuff > dictByPKey
		= new HashMap< CFSecSecFormPKey,
				CFSecSecFormBuff >();
	private Map< CFSecSecFormByClusterIdxKey,
				Map< CFSecSecFormPKey,
					CFSecSecFormBuff >> dictByClusterIdx
		= new HashMap< CFSecSecFormByClusterIdxKey,
				Map< CFSecSecFormPKey,
					CFSecSecFormBuff >>();
	private Map< CFSecSecFormBySecAppIdxKey,
				Map< CFSecSecFormPKey,
					CFSecSecFormBuff >> dictBySecAppIdx
		= new HashMap< CFSecSecFormBySecAppIdxKey,
				Map< CFSecSecFormPKey,
					CFSecSecFormBuff >>();
	private Map< CFSecSecFormByUJEEServletIdxKey,
			CFSecSecFormBuff > dictByUJEEServletIdx
		= new HashMap< CFSecSecFormByUJEEServletIdxKey,
			CFSecSecFormBuff >();

	public CFIntRamSecFormTable( ICFIntSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecForm( CFSecAuthorization Authorization,
		CFSecSecFormBuff Buff )
	{
		final String S_ProcName = "createSecForm";
		CFSecSecFormPKey pkey = schema.getFactorySecForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecFormId( ((CFIntRamClusterTable)schema.getTableCluster()).nextSecFormIdGen( Authorization,
			Buff.getRequiredClusterId() ) );
		Buff.setRequiredClusterId( pkey.getRequiredClusterId() );
		Buff.setRequiredSecFormId( pkey.getRequiredSecFormId() );
		CFSecSecFormByClusterIdxKey keyClusterIdx = schema.getFactorySecForm().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecFormBySecAppIdxKey keySecAppIdx = schema.getFactorySecForm().newSecAppIdxKey();
		keySecAppIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keySecAppIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );

		CFSecSecFormByUJEEServletIdxKey keyUJEEServletIdx = schema.getFactorySecForm().newUJEEServletIdxKey();
		keyUJEEServletIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUJEEServletIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );
		keyUJEEServletIdx.setRequiredJEEServletMapName( Buff.getRequiredJEEServletMapName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUJEEServletIdx.containsKey( keyUJEEServletIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecFormUJEEServletIdx",
				keyUJEEServletIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"SecFormCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecApp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecAppId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecFormApplication",
						"SecApp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictSecAppIdx;
		if( dictBySecAppIdx.containsKey( keySecAppIdx ) ) {
			subdictSecAppIdx = dictBySecAppIdx.get( keySecAppIdx );
		}
		else {
			subdictSecAppIdx = new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictBySecAppIdx.put( keySecAppIdx, subdictSecAppIdx );
		}
		subdictSecAppIdx.put( pkey, Buff );

		dictByUJEEServletIdx.put( keyUJEEServletIdx, Buff );

	}

	public CFSecSecFormBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerived";
		CFSecSecFormPKey key = schema.getFactorySecForm().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecFormId( PKey.getRequiredSecFormId() );
		CFSecSecFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerived";
		CFSecSecFormPKey key = schema.getFactorySecForm().newPKey();
		key.setRequiredClusterId( PKey.getRequiredClusterId() );
		key.setRequiredSecFormId( PKey.getRequiredSecFormId() );
		CFSecSecFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFIntRamSecForm.readAllDerived";
		CFSecSecFormBuff[] retList = new CFSecSecFormBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecFormBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecFormBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerivedByClusterIdx";
		CFSecSecFormByClusterIdxKey key = schema.getFactorySecForm().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecFormBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecFormBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecFormBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictClusterIdx
				= new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecFormBuff[] readDerivedBySecAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerivedBySecAppIdx";
		CFSecSecFormBySecAppIdxKey key = schema.getFactorySecForm().newSecAppIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecAppId( SecAppId );

		CFSecSecFormBuff[] recArray;
		if( dictBySecAppIdx.containsKey( key ) ) {
			Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictSecAppIdx
				= dictBySecAppIdx.get( key );
			recArray = new CFSecSecFormBuff[ subdictSecAppIdx.size() ];
			Iterator< CFSecSecFormBuff > iter = subdictSecAppIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecFormPKey, CFSecSecFormBuff > subdictSecAppIdx
				= new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictBySecAppIdx.put( key, subdictSecAppIdx );
			recArray = new CFSecSecFormBuff[0];
		}
		return( recArray );
	}

	public CFSecSecFormBuff readDerivedByUJEEServletIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId,
		String JEEServletMapName )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerivedByUJEEServletIdx";
		CFSecSecFormByUJEEServletIdxKey key = schema.getFactorySecForm().newUJEEServletIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecAppId( SecAppId );
		key.setRequiredJEEServletMapName( JEEServletMapName );

		CFSecSecFormBuff buff;
		if( dictByUJEEServletIdx.containsKey( key ) ) {
			buff = dictByUJEEServletIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecForm.readDerivedByIdIdx() ";
		CFSecSecFormPKey key = schema.getFactorySecForm().newPKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecFormId( SecFormId );

		CFSecSecFormBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecFormPKey PKey )
	{
		final String S_ProcName = "CFIntRamSecForm.readBuff";
		CFSecSecFormBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00b" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecFormPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecFormBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00b" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecFormBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFIntRamSecForm.readAllBuff";
		CFSecSecFormBuff buff;
		ArrayList<CFSecSecFormBuff> filteredList = new ArrayList<CFSecSecFormBuff>();
		CFSecSecFormBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00b" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecFormBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecForm buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecForm instances in the database accessible for the Authorization.
	 */
	public CFSecSecFormBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorClusterId,
		Integer priorSecFormId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecFormBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecFormId )
	{
		final String S_ProcName = "CFIntRamSecForm.readBuffByIdIdx() ";
		CFSecSecFormBuff buff = readDerivedByIdIdx( Authorization,
			ClusterId,
			SecFormId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00b" ) ) {
			return( (CFSecSecFormBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecFormBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFIntRamSecForm.readBuffByClusterIdx() ";
		CFSecSecFormBuff buff;
		ArrayList<CFSecSecFormBuff> filteredList = new ArrayList<CFSecSecFormBuff>();
		CFSecSecFormBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00b" ) ) {
				filteredList.add( (CFSecSecFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecFormBuff[0] ) );
	}

	public CFSecSecFormBuff[] readBuffBySecAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId )
	{
		final String S_ProcName = "CFIntRamSecForm.readBuffBySecAppIdx() ";
		CFSecSecFormBuff buff;
		ArrayList<CFSecSecFormBuff> filteredList = new ArrayList<CFSecSecFormBuff>();
		CFSecSecFormBuff[] buffList = readDerivedBySecAppIdx( Authorization,
			ClusterId,
			SecAppId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00b" ) ) {
				filteredList.add( (CFSecSecFormBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecFormBuff[0] ) );
	}

	public CFSecSecFormBuff readBuffByUJEEServletIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId,
		String JEEServletMapName )
	{
		final String S_ProcName = "CFIntRamSecForm.readBuffByUJEEServletIdx() ";
		CFSecSecFormBuff buff = readDerivedByUJEEServletIdx( Authorization,
			ClusterId,
			SecAppId,
			JEEServletMapName );
		if( ( buff != null ) && buff.getClassCode().equals( "a00b" ) ) {
			return( (CFSecSecFormBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecForm buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecFormBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		Long priorClusterId,
		Integer priorSecFormId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecForm buffer instances identified by the duplicate key SecAppIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argClusterId	The SecForm key attribute of the instance generating the id.
	 *
	 *	@param	argSecAppId	The SecForm key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecFormBuff[] pageBuffBySecAppIdx( CFSecAuthorization Authorization,
		long ClusterId,
		int SecAppId,
		Long priorClusterId,
		Integer priorSecFormId )
	{
		final String S_ProcName = "pageBuffBySecAppIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecForm( CFSecAuthorization Authorization,
		CFSecSecFormBuff Buff )
	{
		CFSecSecFormPKey pkey = schema.getFactorySecForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecFormId( Buff.getRequiredSecFormId() );
		CFSecSecFormBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecForm",
				"Existing record not found",
				"SecForm",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecForm",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecFormByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecForm().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecFormByClusterIdxKey newKeyClusterIdx = schema.getFactorySecForm().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecFormBySecAppIdxKey existingKeySecAppIdx = schema.getFactorySecForm().newSecAppIdxKey();
		existingKeySecAppIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeySecAppIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );

		CFSecSecFormBySecAppIdxKey newKeySecAppIdx = schema.getFactorySecForm().newSecAppIdxKey();
		newKeySecAppIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeySecAppIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );

		CFSecSecFormByUJEEServletIdxKey existingKeyUJEEServletIdx = schema.getFactorySecForm().newUJEEServletIdxKey();
		existingKeyUJEEServletIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUJEEServletIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );
		existingKeyUJEEServletIdx.setRequiredJEEServletMapName( existing.getRequiredJEEServletMapName() );

		CFSecSecFormByUJEEServletIdxKey newKeyUJEEServletIdx = schema.getFactorySecForm().newUJEEServletIdxKey();
		newKeyUJEEServletIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUJEEServletIdx.setRequiredSecAppId( Buff.getRequiredSecAppId() );
		newKeyUJEEServletIdx.setRequiredJEEServletMapName( Buff.getRequiredJEEServletMapName() );

		// Check unique indexes

		if( ! existingKeyUJEEServletIdx.equals( newKeyUJEEServletIdx ) ) {
			if( dictByUJEEServletIdx.containsKey( newKeyUJEEServletIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecForm",
					"SecFormUJEEServletIdx",
					newKeyUJEEServletIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecForm",
						"Owner",
						"SecFormCluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecApp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId(),
						Buff.getRequiredSecAppId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecForm",
						"Container",
						"SecFormApplication",
						"SecApp",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecFormPKey, CFSecSecFormBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySecAppIdx.get( existingKeySecAppIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySecAppIdx.containsKey( newKeySecAppIdx ) ) {
			subdict = dictBySecAppIdx.get( newKeySecAppIdx );
		}
		else {
			subdict = new HashMap< CFSecSecFormPKey, CFSecSecFormBuff >();
			dictBySecAppIdx.put( newKeySecAppIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUJEEServletIdx.remove( existingKeyUJEEServletIdx );
		dictByUJEEServletIdx.put( newKeyUJEEServletIdx, Buff );

	}

	public void deleteSecForm( CFSecAuthorization Authorization,
		CFSecSecFormBuff Buff )
	{
		final String S_ProcName = "CFIntRamSecFormTable.deleteSecForm() ";
		String classCode;
		CFSecSecFormPKey pkey = schema.getFactorySecForm().newPKey();
		pkey.setRequiredClusterId( Buff.getRequiredClusterId() );
		pkey.setRequiredSecFormId( Buff.getRequiredSecFormId() );
		CFSecSecFormBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecForm",
				pkey );
		}
		CFSecSecFormByClusterIdxKey keyClusterIdx = schema.getFactorySecForm().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecFormBySecAppIdxKey keySecAppIdx = schema.getFactorySecForm().newSecAppIdxKey();
		keySecAppIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keySecAppIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );

		CFSecSecFormByUJEEServletIdxKey keyUJEEServletIdx = schema.getFactorySecForm().newUJEEServletIdxKey();
		keyUJEEServletIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUJEEServletIdx.setRequiredSecAppId( existing.getRequiredSecAppId() );
		keyUJEEServletIdx.setRequiredJEEServletMapName( existing.getRequiredJEEServletMapName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecFormPKey, CFSecSecFormBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictBySecAppIdx.get( keySecAppIdx );
		subdict.remove( pkey );

		dictByUJEEServletIdx.remove( keyUJEEServletIdx );

	}
	public void deleteSecFormByIdIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecFormId )
	{
		CFSecSecFormPKey key = schema.getFactorySecForm().newPKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecFormId( argSecFormId );
		deleteSecFormByIdIdx( Authorization, key );
	}

	public void deleteSecFormByIdIdx( CFSecAuthorization Authorization,
		CFSecSecFormPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecFormBuff cur;
		LinkedList<CFSecSecFormBuff> matchSet = new LinkedList<CFSecSecFormBuff>();
		Iterator<CFSecSecFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecFormId() );
			deleteSecForm( Authorization, cur );
		}
	}

	public void deleteSecFormByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecFormByClusterIdxKey key = schema.getFactorySecForm().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecFormByClusterIdx( Authorization, key );
	}

	public void deleteSecFormByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecFormByClusterIdxKey argKey )
	{
		CFSecSecFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecFormBuff> matchSet = new LinkedList<CFSecSecFormBuff>();
		Iterator<CFSecSecFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecFormId() );
			deleteSecForm( Authorization, cur );
		}
	}

	public void deleteSecFormBySecAppIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecAppId )
	{
		CFSecSecFormBySecAppIdxKey key = schema.getFactorySecForm().newSecAppIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecAppId( argSecAppId );
		deleteSecFormBySecAppIdx( Authorization, key );
	}

	public void deleteSecFormBySecAppIdx( CFSecAuthorization Authorization,
		CFSecSecFormBySecAppIdxKey argKey )
	{
		CFSecSecFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecFormBuff> matchSet = new LinkedList<CFSecSecFormBuff>();
		Iterator<CFSecSecFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecFormId() );
			deleteSecForm( Authorization, cur );
		}
	}

	public void deleteSecFormByUJEEServletIdx( CFSecAuthorization Authorization,
		long argClusterId,
		int argSecAppId,
		String argJEEServletMapName )
	{
		CFSecSecFormByUJEEServletIdxKey key = schema.getFactorySecForm().newUJEEServletIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecAppId( argSecAppId );
		key.setRequiredJEEServletMapName( argJEEServletMapName );
		deleteSecFormByUJEEServletIdx( Authorization, key );
	}

	public void deleteSecFormByUJEEServletIdx( CFSecAuthorization Authorization,
		CFSecSecFormByUJEEServletIdxKey argKey )
	{
		CFSecSecFormBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecFormBuff> matchSet = new LinkedList<CFSecSecFormBuff>();
		Iterator<CFSecSecFormBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecFormBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecForm().readDerivedByIdIdx( Authorization,
				cur.getRequiredClusterId(),
				cur.getRequiredSecFormId() );
			deleteSecForm( Authorization, cur );
		}
	}

	public void releasePreparedStatements() {
	}
}
